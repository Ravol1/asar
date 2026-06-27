/**
* @file asar_packer.cpp
 * @brief Implementation of the ASAR archive packer.
 *
 *
 * This file implements packer::open(), packer::save(), packer::close(),
 * and the private helpers that build the metadata tree and hash each file.
 */


#include "asar.h"

#include <nlohmann/json.hpp>
#include <filesystem>
#include <stdexcept>
#include <map>
#include <fstream>
#include <openssl/evp.h>

#ifndef _WIN32
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#endif





using json = nlohmann::json;
namespace fs = std::filesystem;

constexpr size_t MEGABYTE_TO_BYTE = 1024 * 1024;		/// Number of bytes in one mebibyte (1 MiB).


/**
 * @brief Size of each hashing block in bytes (4 MiB).
 *
 * Files are split into chunks of this size when computing per-block SHA-256
 * hashes. Electron's integrity verification expects exactly this granularity.
 */
constexpr size_t BLOCK_SIZE = 4 * MEGABYTE_TO_BYTE;


namespace asar {

	/**
	 * @brief Returns the serialized JSON metadata string.
	 * @throws std::logic_error if the archive has not been opened yet.
	 */
	std::string_view packer::json_string() {
		if (!_is_open) throw std::logic_error("Archive not open");

		return _json_string;
	}



	/**
	 * @brief Returns a read-only view of the packed file-data blob.
	 *
	 * The blob is a flat byte array in which every file's content sits at the
	 * offset recorded in the JSON metadata.
	 *
	 * @throws std::logic_error if the archive has not been opened yet.
	 */
	std::span<const uint8_t> packer::data() {
		if (!_is_open) throw std::logic_error("Archive not open");

		return _data;
	}



	/**
	 * @brief Returns the full JSON metadata object.
	 * @throws std::logic_error if the archive has not been opened yet.
	 */
	json packer::metadata() {
		if (!_is_open) throw std::logic_error("Archive not open");

		return _metadata;
	}





	/**
	 * @brief Converts a raw byte buffer to its lowercase hexadecimal string.
	 *
	 * Used to produce human-readable SHA-256 digests that match the format
	 * expected by Electron's ASAR integrity checker.
	 *
	 * @param data  Byte span to encode.
	 * @return      Hex-encoded string (2 characters per input byte).
	 */
	static std::string hash_to_hex(const std::span<const uint8_t> data) {
		static constexpr char hex_chars[] = "0123456789abcdef";
		std::string res;
		res.reserve(data.size() * 2);

		for (const uint8_t b : data) {
			res.push_back(hex_chars[b >> 4]);		// high nibble
			res.push_back(hex_chars[b & 0x0F]);		// low nibble
		}
		return res;
	}



	/**
	 * @brief Computes SHA-256 integrity data for an in-memory file buffer.
	 *
	 * Two levels of hashing are performed to match Electron's expectations:
	 *   - **Block hashes**: one SHA-256 per BLOCK_SIZE-byte chunk of @p data.
	 *   - **Full hash**:    a single SHA-256 over the entire @p data buffer,
	 *                       computed incrementally alongside the block hashes
	 *                       so the data is read only once.
	 *
	 * Both digests are stored as lowercase hex strings.
	 *
	 * @param data  Read-only span over the file's raw bytes.
	 * @return      An IntegrityData struct containing the full hash and the
	 *              vector of per-block hashes.
	 */
	static IntegrityData hash_data(const std::span<const uint8_t> data) {
		IntegrityData result;
		result.blocks = std::vector<std::string>();

		const size_t tot_size = data.size();


		// Allocate two OpenSSL digest contexts:
		//   block_ctx - reset for every BLOCK_SIZE chunk
		//   full_ctx  - accumulates bytes across all chunks for the final hash
		EVP_MD_CTX* block_ctx = EVP_MD_CTX_new();
		EVP_MD_CTX* full_ctx = EVP_MD_CTX_new();

		EVP_DigestInit_ex(full_ctx, EVP_sha256(), nullptr);

		// Iterate over the data in BLOCK_SIZE windows.
		for (size_t i = 0; i < tot_size; i += BLOCK_SIZE) {
			unsigned char hash[EVP_MAX_MD_SIZE];
			unsigned int len_of_hash = 0;

			// The last chunk may be smaller than BLOCK_SIZE.
			const size_t chunk_len = std::min(BLOCK_SIZE, tot_size - i);
			auto block = data.subspan(i, chunk_len);

			// Hash the current chunk on its own.
			EVP_DigestInit_ex(block_ctx, EVP_sha256(), nullptr);
			EVP_DigestUpdate(block_ctx, block.data(), block.size());
			EVP_DigestUpdate(full_ctx, block.data(), block.size());

			EVP_DigestFinal_ex(block_ctx, hash, &len_of_hash);

			result.blocks.push_back(hash_to_hex(std::span(hash, len_of_hash)));
		}

		// Finalize the full-file hash after all blocks have been processed.
		unsigned char hash[EVP_MAX_MD_SIZE];
		unsigned int len_of_hash = 0;
		EVP_DigestFinal_ex(full_ctx, hash, &len_of_hash);

		EVP_MD_CTX_free(block_ctx);
		EVP_MD_CTX_free(full_ctx);

		result.final_hash = hash_to_hex(std::span(hash, len_of_hash));

		return result;
	}



	/**
	 * @brief Reads every file listed in file_tasks into _data and fills in
	 *        their integrity information in the JSON metadata tree.
	 *
	 * Each FileTask records the destination offset inside _data, the expected
	 * byte count, the source path on disk, and a pointer to the JSON node that
	 * must be updated with the computed hashes.
	 *
	 * @throws std::runtime_error if any file cannot be opened, read, or closed.
	 */
	void packer::construct_data() {
		for(const auto& [path, size, offset, node] : file_tasks){

			// Create a sub-span view into _data at the correct offset for
			// this file so fread writes directly into the output buffer.
			std::span file_data(_data.data() + offset, size);


			// Platform-specific file open: _wfopen_s on Windows for wide-character path support;
			// standard fopen on all other platforms.
		#ifdef _WIN32
			FILE* fp;
			errno_t err = _wfopen_s(&fp, path.c_str(), L"rb");
			if (err != 0) throw std::runtime_error("Error opening file " + path.string());
		#else
			FILE* fp = fopen(path.c_str(), "rb");
		#endif

			if (!fp) throw std::runtime_error("Error opening file " + path.string());

			if (const size_t read = fread(file_data.data(), 1, size, fp); read != size)
				throw std::runtime_error("Error reading file " + path.string());

			if (fclose(fp) != 0) throw std::runtime_error("Error closing file " + path.string());


			// Compute SHA-256 hashes for this file's data and write them into
			// the "integrity" sub-object of its JSON metadata node.
			json* integrity = &(*node)["integrity"];
			auto [final_hash, blocks] = hash_data(file_data);

			(*integrity)["blocks"] = blocks;
			(*integrity)["hash"] = final_hash;
		}
	}



	/**
	 * @brief Recursively builds the JSON metadata tree for a directory.
	 *
	 * The function mirrors the on-disk directory structure:
	 *   - Directories become JSON objects with a "files" key whose value is
	 *     another object produced by a recursive call.
	 *   - Files get an object with "offset", "size", and a placeholder
	 *     "integrity" block (hashes are filled in later by construct_data()).
	 *
	 * A std::map is used so that sibling entries are always iterated in
	 * alphabetical order, giving deterministic JSON output regardless of
	 * the underlying filesystem's ordering.
	 *
	 * As each file is visited, a FileTask is appended to file_tasks so that
	 * construct_data() knows where in _data to write it. tot_offset is
	 * advanced by each file's size to produce sequential, non-overlapping
	 * offsets.
	 *
	 * @param node          Pointer to the JSON object node to populate.
	 * @param current_path  Directory on disk to enumerate.
	 */
	void packer::construct_metadata(json* node, const fs::path& current_path) {
		// SHA-256 produces a 32-byte (256-bit) hash, represented as a 64-character hexadecimal string
		const auto placeholder_hash = std::string(64, '0');


		// Use a sorted map to guarantee alphabetical ordering in the output.
		std::map<std::string, fs::path> dir_map;

		*node = json::object();

		// Collect all directory entries, converting the filename to a UTF-8
		// std::string for use as a JSON key and map key.
		for (auto& entry : fs::directory_iterator(current_path)) {
			std::u8string u8name = entry.path().filename().u8string();
			std::string entry_name(reinterpret_cast<const char*>(u8name.c_str()));

			dir_map[entry_name] = entry.path();
		}

		for (auto& [entry_name, entry_path] : dir_map) {
			json* next_node = &(*node)[entry_name];

			if (fs::is_directory(entry_path)) {
				// Recurse: directories are represented as { "files": { ... } }
				construct_metadata(&(*next_node)["files"], entry_path);
			}
			else {
				// File node:
				// record offset (as string, per ASAR spec),
				// size (as integer, per ASAR spec),
				// and a placeholder integrity block to be filled in later.


				uint64_t size = fs::file_size(entry_path);

				(*next_node)["offset"] = std::to_string(_data_size);
				(*next_node)["size"] = size;

				json* integrity = &(*next_node)["integrity"];
				(*integrity)["algorithm"] = "SHA256";
				(*integrity)["hash"] = placeholder_hash;	// placeholder, filled by construct_data()
				(*integrity)["blockSize"] = BLOCK_SIZE;
				(*integrity)["blocks"] = json::array();		// filled by construct_data()


				const auto block_number = (size + BLOCK_SIZE - 1) / BLOCK_SIZE;
				for (int i = 0; i < block_number; i++) {
					(*integrity)["blocks"][i] = placeholder_hash;
				}


				// Register the file so construct_data() can read it, hash it
				// and place it in the correct position within the data block.
				FileTask file_task;
				file_task.path = entry_path;
				file_task.size = size;
				file_task.offset = _data_size;
				file_task.node = next_node;

				file_tasks.push_back(file_task);

				// Advance the write cursor past this file's region in _data.
				_data_size += size;
			}
		}
	}



	/**
	 * @brief Opens a directory and prepares it for packing into an ASAR archive.
	 *
	 * Walks the given directory to build a JSON metadata tree, computes the
	 * archive layout (header + JSON block + raw data blob), and memory-maps
	 * (POSIX) or heap-allocates (Windows) the output buffer. File data is then
	 * written into the buffer via construct_data(). The final JSON string
	 * (which now includes hashes) is stored for later use by save().
	 *
	 * @param dir        Source directory to pack.
	 * @param save_dest  Destination file path; used on POSIX to create and
	 *                   size the output file before mmap-ing it.
	 * @throws std::logic_error    if the archive is already open, or if
	 *                             @p dir does not exist.
	 * @throws std::system_error   if open(2), ftruncate(2), or fstat(2) fail
	 *                             (POSIX only).
	 * @throws std::runtime_error  if mmap(2) fails (POSIX only).
	 */
	void packer::open(const fs::path& dir, const fs::path& save_dest) {
		if (_is_open) throw std::logic_error("Archive already open");
		if (!fs::exists(dir)) throw std::logic_error("Directory does not exist");

		_root = dir;


		// Recurse through the directory tree, populating _metadata["files"]
		// with per-file entries (path, size, offset) and accumulating _data_size.
		construct_metadata(&_metadata["files"], dir);


		// Save temporary JSON string without hashes.
		const auto json_string_tmp = _metadata.dump();



		// Fill in the fixed AsarHeader fields:
		//   signature  – magic byte expected by Electron's asar reader.
		//   json_size  – raw byte length of the JSON metadata string.
		//   pickle2    – json_size rounded up to the next 4-byte boundary, plus
		//                the 4-byte pickle size prefix; this is the total size of
		//                the JSON block as seen by Electron's pickle reader.
		//   pickle3    – pickle2 + 4
		header.signature = 0x04;
		header.json_size = json_string_tmp.size();
		header.pickle2 = (header.json_size + 3) / 4 * 4 + 4;
		header.pickle3 = header.pickle2 + 4;


		// Compute absolute offsets within the output buffer:
		//   json_offset  – immediately after the fixed AsarHeader struct.
		//   data_offset  – immediately after the padded JSON block.
		//   _tot_size    – total byte length of the final archive file.
		constexpr auto json_offset = sizeof(AsarHeader);
		const auto data_offset = json_offset + header.pickle2;
		_tot_size = sizeof(AsarHeader) + header.pickle2 + _data_size;


#ifdef _WIN32
		// Windows: allocate the entire archive in a heap buffer; _data is a
		// span over the file-data region at the end of that buffer.


		_file_data = new[tot_size];
		_data = std::span(_file_data + data_offset, _data_size);
#else
		// POSIX: create (or truncate) the destination file, extend it to the
		// final archive size, then mmap the whole file read-write so that
		// construct_data() can write directly into it without extra copies.


		const int fd = ::open(save_dest.c_str(), O_RDWR | O_CREAT, 0644);
		if (fd == -1)
			throw std::system_error(errno, std::generic_category(), "open");

		// Pre-allocate the exact number of bytes the finished archive will need.
		if (ftruncate(fd, static_cast<__off_t>(_tot_size)) == -1)
			throw std::system_error(errno, std::generic_category(), "ftruncate");

		struct stat st{};

		if (::fstat(fd, &st) == -1) {
			::close(fd);
			throw std::system_error(errno, std::generic_category(), "fstat");
		}

		// Map the file into the address space
		_file_data = static_cast<uint8_t*>(
			mmap(nullptr, _tot_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)
		);

		// The fd is no longer needed once the mapping is established.
		::close(fd);

		if (_file_data == MAP_FAILED)
			throw std::runtime_error("mmap error.");


		// _data is a span over only the file-data region of the mapped buffer,
		// keeping header/JSON writes separate from raw file content writes
		_data = std::span(_file_data + data_offset, _data_size);

#endif

		// Copy all source files into the mapped/allocated buffer and update
		// each metadata entry with the computed SHA-256 hash.
		construct_data();


		// Re-serialize the metadata now that construct_data() has filled in file hashes;
		// this is the string that will actually be written to disk.
		_json_string = _metadata.dump();


		_is_open = true;
	}



	/**
	 * @brief Releases all resources associated with the open archive.
	 *
	 * Safe to call on an already-closed packer (no-op). After returning, the
	 * packer may be reused by calling open() again.
	 */
	void packer::close() {
		if (!_is_open) return;

#ifdef _WIN32
		delete[] _file_data;
#else
		// Unmap the memory-mapped file region; this also flushes any dirty
		// pages back to the underlying file before the mapping is removed.
		munmap(_file_data, _tot_size);
#endif
		_file_data = nullptr;
		_data_size = 0;


		// Release JSON object memory in three steps: clear internal nodes,
		// swap with a default-constructed (empty) JSON to release heap storage,
		// then assign null so the object is in a well-defined empty state.
		_metadata.clear();
		json().swap(_metadata);
		_metadata = nullptr;


		// Release the serialized JSON string's heap allocation entirely rather
		// than just setting size to zero (clear() alone may retain capacity).
		_json_string.clear();
		_json_string.shrink_to_fit();

		_is_open = false;
	}


	/**
	 * @brief Writes the finished ASAR archive to disk.
	 *
	 * The on-disk layout is:
	 * ```
	 * [ AsarHeader (fixed size) ]
	 * [ JSON metadata string    ]
	 * [ NUL padding (0–3 bytes) ]
	 * [ Raw file data blob      ]
	 * ```
	 *
	 * The padding ensures that Electron's pickle reader, which works in
	 * 4-byte units, does not read past the end of the JSON block.
	 *
	 * @param path  Destination file path for the .asar archive.
	 * @throws std::logic_error    if the archive has not been opened yet.
	 * @throws std::runtime_error  if the output file cannot be created.
	 */
	void packer::save(const fs::path& path) {
#ifdef _WIN32
		if (!_is_open) throw std::logic_error("Archive not open");


		std::ofstream file(path, std::ios::out | std::ios::binary);

		if (!file) throw std::runtime_error("Unable to open file " + path.string());


		// Fixed-size binary header (signature, sizes, offsets).
		file.write(reinterpret_cast<char*>(&header), sizeof(AsarHeader));

		// Raw JSON metadata string (no null terminator; length is encoded in
		// the header so Electron knows exactly how many bytes to read)
		file.write(
			_json_string.data(),
			static_cast<std::streamsize>(_json_string.size()));


		// NUL padding so the JSON block ends on a 4-byte boundary.
		// pickle2 = json_size_prefix(4) + json_size rounded up to 4 bytes,
		// so pad_size = pickle2 - json_size - 4 gives 0–3 bytes of padding
		if (const uint32_t pad_size = header.pickle2 - header.json_size - 4; pad_size > 0) {
			constexpr char padding[3] = { 0, 0, 0 };
			file.write(padding, pad_size);
		}

		file.close();
#else
		// POSIX: the output file is already mmap-ed and fully populated.
		// Only the header and JSON string need to be stamped in; file data was
		// written directly into the mapped region during construct_data().
		// Padding bytes are implicitly zero because ftruncate() zero-fills the
		// file on creation, so no explicit pad write is required here.


		memcpy(_file_data, &header, sizeof(AsarHeader));
		memcpy(_file_data + sizeof(AsarHeader), _json_string.data(), _json_string.size());
#endif
	}
} // namespace asar