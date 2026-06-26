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
	json packer::metadata()
	{
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

				(*next_node)["offset"] = std::to_string(tot_offset);
				(*next_node)["size"] = size;

				json* integrity = &(*next_node)["integrity"];
				(*integrity)["algorithm"] = "SHA256";
				(*integrity)["hash"] = "";				// filled by construct_data()
				(*integrity)["blockSize"] = BLOCK_SIZE;
				(*integrity)["blocks"] = json::array();		// filled by construct_data()


				// Register the file so construct_data() can read it, hash it
				// and place it in the correct position within the data block.
				FileTask file_task;
				file_task.path = entry_path;
				file_task.size = size;
				file_task.offset = tot_offset;
				file_task.node = next_node;

				file_tasks.push_back(file_task);

				// Advance the write cursor past this file's region in _data.
				tot_offset += size;
			}
		}
	}



	/**
	 * @brief Opens a directory and builds the complete in-memory ASAR archive.
	 *
	 * Steps performed:
	 *   1. construct_metadata() – walks the directory tree and builds the JSON
	 *      header, recording file offsets and populating file_tasks.
	 *   2. Allocates _data to the total byte size of all files and populate it with construct_data().
	 *   3. Serializes _metadata to _json_string.
	 *   4. Fills in the binary AsarHeader fields (see AsarHeader docs):
	 *        - signature  : always 0x04 (Electron's pickle protocol marker).
	 *        - json_size  : byte length of the serialized JSON string.
	 *        - pickle2    : JSON size rounded up to a 4-byte boundary, plus 4.
	 *        - pickle3    : pickle2 + 4 (outer pickle size field).
	 *
	 * @param dir  Path to the root directory to archive.
	 * @throws std::logic_error  if an archive is already open, or if @p dir
	 *                           does not exist.
	 */
	void packer::open(const fs::path& dir) {
		if (_is_open) throw std::logic_error("Archive already open");
		if (!fs::exists(dir)) throw std::logic_error("Directory does not exist");

		root = dir;


		// Step 1: build metadata tree and record all file tasks.
		construct_metadata(&_metadata["files"], dir);


		// Step 2: allocate flat output buffer and fill it with file contents.
		_data = std::vector<uint8_t>(tot_offset);
		construct_data();


		// Step 3: serialise metadata to JSON string.
		_json_string = _metadata.dump();


		// Phase 4: populate the binary header.
		header.signature = 0x04;
		header.json_size = _json_string.size();
		header.pickle2 = (header.json_size + 3) / 4 * 4 + 4;
		header.pickle3 = header.pickle2 + 4;

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

		tot_offset = 0;


		// Free JSON memory: clear(), swap with empty, then assign null.
		_metadata.clear();
		json().swap(_metadata);
		_metadata = nullptr;


		// Shrink string and vector back to zero capacity.
		_json_string.clear();
		_json_string.shrink_to_fit();
		_data.clear();
		_data.shrink_to_fit();


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
		if (!_is_open) throw std::logic_error("Archive not open");

		std::ofstream file(path, std::ios::out | std::ios::binary);

		if (!file) throw std::runtime_error("Unable to open file " + path.string());


		// Binary header.
		file.write(reinterpret_cast<char*>(&header), sizeof(AsarHeader));

		// JSON metadata string (no null terminator – length is in header).
		file.write(
			_json_string.data(),
			static_cast<std::streamsize>(_json_string.size()));


		// NUL padding to align the end of the header region to 4 bytes.
		// pickle2 already encodes the padded size; subtract json_size and
		// the 4-byte json_size prefix to find how many pad bytes are needed.
		if (const uint32_t pad_size = header.pickle2 - header.json_size - 4; pad_size > 0) {
			constexpr char padding[3] = { 0, 0, 0 };
			file.write(padding, pad_size);
		}

		// 4. Raw concatenated file data.
		file.write(
			reinterpret_cast<char*>(_data.data()),
			static_cast<std::streamsize>(_data.size()));

		file.close();
	}
} // namespace asar