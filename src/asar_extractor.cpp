/**
 * @file asar_extractor.cpp
 * @brief Implementation of the ASAR archive extractor.
 *
 *
 * This file implements extractor::open(), extractor::save(), extractor::close(),
 * and the private helpers that build the metadata tree and hash each file.
 */


#include "asar.h"

#include <fstream>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>

using json = nlohmann::json;
namespace fs = std::filesystem;


namespace asar {
	/**
	 * @brief Returns a read-only view of the entire raw file buffer.
	 *
	 * The buffer contains every byte of the .asar file as loaded from disk.
	 * Useful for low-level inspection or re-serialization.
	 *
	 * @throws std::logic_error if the archive has not been opened yet.
	 */
	std::span<const uint8_t> extractor::buff() {
		if (!_is_open) throw std::logic_error("Archive not open");

		return std::span(_buff);
	}



	/**
	 * @brief Returns a string view over the raw JSON metadata portion of the
	 *        buffer (no copy; valid only while the archive is open).
	 *
	 * @throws std::logic_error if the archive has not been opened yet.
	 */
	std::string_view extractor::json_string() const {
		if (!_is_open) throw std::logic_error("Archive not open");

		return _json_string;
	}



	/**
	 * @brief Returns a read-only view of the file-data blob.
	 *
	 * This is the region of the buffer that starts immediately after the
	 * (padded) JSON header.
	 *
	 * @throws std::logic_error if the archive has not been opened yet.
	 */
	std::span<const uint8_t> extractor::data() const {
		if (!_is_open) throw std::logic_error("Archive not open");

		return _data;
	}



	/**
	 * @brief Returns the parsed JSON metadata object.
	 * @throws std::logic_error if the archive has not been opened yet.
	 */
	json extractor::metadata(){
		if (!_is_open) throw std::logic_error("Archive not open");

		return _metadata;
	}





	/**
	 * @brief Validates the binary header of an ASAR file.
	 *
	 * Currently only checks the signature byte (must equal 0x04), which is
	 * the Electron pickle-protocol marker.
	 *
	 * @param header  The header struct read from the start of the file.
	 * @return true if the header looks valid, false otherwise.
	 */
	static bool check_header(const AsarHeader& header) {
		return header.signature == 0x04;
	}



	/**
	 * @brief Navigates the JSON metadata tree to find the node for a given path.
	 *
	 * The path is treated as a sequence of filename segments (e.g. "src/main.js"
	 * becomes ["src", "main.js"]). At each step the function descends into the
	 * current directory's children; if the child is itself a directory its
	 * "files" sub-object becomes the new search context, otherwise the search
	 * context is set to null so any further segments will return nullptr.
	 *
	 * Example metadata shape navigated by this function:
	 * @code
	 * {
	 *   "files": {
	 *     "src": {
	 *       "files": {
	 *         "main.js": { "offset": "0", "size": 1234, "integrity": { ... } }
	 *       }
	 *     }
	 *   }
	 * }
	 * @endcode
	 *
	 * @param path  Relative path within the archive (e.g. "src/main.js").
	 * @return      Pointer to the matching JSON node, or nullptr if not found.
	 * @throws std::logic_error if the archive is not open.
	 */
	const json* extractor::find_node(const std::filesystem::path& path) {
		if (!_is_open) throw std::logic_error("Archive not open.");

		const json* curr_node = &_metadata["files"];		// start at the archive root
		const json* new_node = nullptr;
		std::vector<std::string> segments;

		for (auto& segment_path : path) {
			if (curr_node == nullptr) return nullptr;		// exhausted directory depth

			std::string segment = segment_path.string();

			// Look up this path segment among the current directory's children.
			auto it = curr_node->find(segment);
			if (it == curr_node->end()) return nullptr;

			new_node = &*it;

			// If the matched node has a "files" key it is a directory; descend
			// into it so the next segment searches within that directory.
			auto new_it = new_node->find("files");
			if (new_it != new_node->end()) curr_node = &*new_it;
			else curr_node = nullptr;
		}

		return new_node;
	}



	/**
	 * @brief Returns a span over the raw bytes of a single file entry.
	 *
	 * Reads the "offset" (stored as a decimal string per ASAR spec) and "size"
	 * (stored as an integer) from @p json_node, then slices the corresponding
	 * region out of _data.
	 *
	 * @param json_node  Pointer to a file entry node in the metadata tree.
	 * @return           A read-only span over the file's bytes inside _data.
	 * @throws std::logic_error    if the archive is not open, or if @p json_node
	 *                             is missing "size" or "offset".
	 * @throws std::runtime_error  if "offset" is not a string, if "size" is not
	 *                             an integer, or if the string-to-number
	 *                             conversion fails.
	 */
	std::span<const uint8_t> extractor::get_file_data(const json* json_node) {
		if (!_is_open) throw std::logic_error("Archive not open.");
		if (!(json_node->contains("size") && json_node->contains("offset")))
			throw std::logic_error("Invalid file entry.");

		const json* offset_node = &(*json_node)["offset"];
		const json* size_node = &(*json_node)["size"];
		size_t offset;
		size_t size;


		// The ASAR spec stores offset as a decimal string.
		// Parse it with from_chars for safe, locale-independent conversion.
		if (offset_node->is_string()) {
			auto const& str = offset_node->get_ref<std::string const&>();
			if (auto [ptr, ec] = std::from_chars(str.data(), str.data() + str.size(), offset);
				ec != std::errc()) {
				throw std::runtime_error("Unexpected error");
				}
		}
		else throw std::runtime_error("Bad data format.");


		// Size is stored as an integer
		if (size_node->is_number_integer()) size = size_node->get<size_t>();

		else throw std::runtime_error("Bad data format.");


		return {_data.data() + offset, size};
	}



	/**
	 * @brief Writes a single archived file to a path on disk.
	 *
	 * Retrieves the file's bytes via get_file_data(), then writes them to
	 * @p path using platform-appropriate file I/O (wide-character path on
	 * Windows; narrow path on all other platforms).
	 *
	 * @param file_node  JSON metadata node for the file to extract.
	 * @param path       Destination path on disk (parent directory must exist).
	 *
	 * @throws std::runtime_error  if the destination file cannot be opened,
	 *                             if the write is incomplete, or if fclose fails.
	 */
	void extractor::extract_file(const json* file_node, const fs::path& path) {
		std::span file_data = get_file_data(file_node);
		size_t bytes = file_data.size();


		// Platform-specific open: _wfopen_s on Windows for wide-character paths.
	#ifdef _WIN32
		FILE* fp;
		errno_t err = _wfopen_s(&fp, path.c_str(), L"wb");

		if (err != 0) throw std::runtime_error("Error opening file " + path.string());;
	#else
		FILE* fp = fopen(path.c_str(), "wb");
	#endif

		if (!fp) throw std::runtime_error("Error opening file " + path.string());

		size_t written = fwrite(file_data.data(), 1, bytes, fp);

		if (written != bytes) throw std::runtime_error("Error writing file " + path.string());

		if (fclose(fp) != 0) throw std::runtime_error("Error closing file " + path.string());

	}



	/**
	 * @brief Recursively walks a metadata subtree and extracts every entry.
	 *
	 * For each entry in @p node:
	 *   - If the entry has a "files" key it is a directory: create the
	 *     corresponding directory on disk and recurse into it.
	 *   - If the entry has an "offset" key it is a regular file: extract it
	 *     via extract_file().
	 *
	 * Entry names are re-encoded as UTF-8 std::filesystem paths so that
	 * non-ASCII filenames (e.g. CJK characters) are preserved correctly on
	 * all platforms.
	 *
	 * @param node          Pointer to the "files" object of the current directory
	 *                      in the JSON metadata tree.
	 * @param current_path  Destination directory on disk for this level of the tree.
	 */
	void extractor::iterate_entries(const json* node, const fs::path& current_path) {
		for (auto& [name, value] : node->items()) {
			// Re-encode the JSON key (UTF-8 std::string) as a std::u8string so
			// std::filesystem handles non-ASCII names portably.
			std::u8string name_u8(reinterpret_cast<const char8_t*>(name.data()), name.size());

			fs::path new_path = current_path / name_u8;


			// Prevent path traversal attacks: ensure new_path resolves to a location
			// inside current_path. weakly_canonical resolves ".." without requiring the
			// path to exist; mismatch then walks both iterator ranges and stops at the
			// first differing component. If the canonical destination is not fully
			// consumed (a != end), new_path escapes the intended root.
			fs::path canonical_dest = fs::weakly_canonical(current_path);
			fs::path canonical_new  = fs::weakly_canonical(new_path);

			auto [a, b] = std::mismatch(
			canonical_dest.begin(), canonical_dest.end(),
			canonical_new.begin(), canonical_new.end()
			);

			if (a != canonical_dest.end()) {
				throw std::runtime_error("Path traversal detected: " + new_path.string());
			}



			if (value.contains("files")) {
				// Directory node: ensure the directory exists, then recurse.
				fs::create_directories(new_path);
				iterate_entries(&value["files"], new_path);
			}

			else if (value.contains("offset")) {
				this->extract_file(&value, new_path);
			}

			// Entries with neither "files" nor "offset" are silently skipped
		}
	}



	/**
	 * @brief Extracts the entire archive to a destination directory.
	 *
	 * Calls iterate_entries() starting from the root "files" node, which
	 * recursively recreates the full directory tree under @p dest.
	 *
	 * @param dest  Root destination directory. It need not exist beforehand;
	 *              iterate_entries() calls fs::create_directories() as needed.
	 * @throws std::logic_error if the archive is not open.
	 */
	void extractor::extract_all(const fs::path& dest) {
		if (!_is_open) throw std::logic_error("Archive not open.");

		const json* first_node = &_metadata["files"];
		iterate_entries(first_node, dest);
	}





	/**
	 * @brief Opens and fully loads an ASAR archive from disk into memory.
	 *
	 * Steps performed:
	 *   1. Read the entire file into _buff in a single binary read.
	 *   2. Copy and validate AsarHeader from the start of _buff.
	 *   3. Set _json_string to a string_view over the JSON region of _buff
	 *   4. Calculate the data-blob start offset
	 *   5. Set _data to a span over the remainder of _buff.
	 *   6. Parse _json_string into the _metadata JSON object.
	 *
	 * @param filepath  Path to the .asar file to open.
	 * @throws std::logic_error    if an archive is already open.
	 * @throws std::runtime_error  if the file cannot be opened or read, if the
	 *                             file is too small to contain a valid header,
	 *                             if the header signature is wrong, or if the
	 *                             JSON metadata cannot be parsed.
	 */
	void extractor::open(const fs::path& filepath) {
		if (_is_open) throw std::logic_error("Archive already open.");


		std::intmax_t tot_size = 0;

		std::ifstream file;
		file.open(filepath, std::ios::in | std::ios::binary);

		if (!file.is_open()) throw std::runtime_error("Unable to open file at: " + filepath.string() + ". Does it exist?");


		// Determine file size by seeking to the end, then rewind.
		file.seekg(0, std::ios::end);
		tot_size = file.tellg();
		file.seekg(0, std::ios::beg);


		// Read the entire file into _buff in one call.
		_buff = std::vector<uint8_t>(tot_size);
		if (!file.read(reinterpret_cast<char*>(_buff.data()), tot_size)) throw std::runtime_error("Read error.");
		file.close();

		size_t size = _buff.size();


		// Validate the binary header
		AsarHeader header{};
		if (size < sizeof(AsarHeader)) throw std::runtime_error("Wrong file format");

		std::memcpy(&header, _buff.data(), sizeof(AsarHeader));

		if (!check_header(header)) throw std::runtime_error("Wrong file format.");


		// Read JSON string
		const size_t json_size = header.json_size;
		_json_string = std::string_view(reinterpret_cast<const char*>(_buff.data()) + sizeof(AsarHeader), json_size);


		// The JSON block is stored with 4-byte alignment (Electron pickle format).
		// Round json_size up to the next multiple of 4 to find where file data begins.
		size_t data_start_offset = sizeof(AsarHeader) + (header.json_size + 3) / 4 * 4;


		// Expose the raw file-data blob
		size_t data_size = size - data_start_offset;
		_data = std::span<const uint8_t>(_buff.data() + data_start_offset, data_size);


		// Parse JSON
		try {
			_metadata = json::parse(_json_string);
		}
		catch (json::parse_error&) {
			throw std::runtime_error("Couldn't parse json string");
		}


		_is_open = true;
	}



	/**
	 * @brief Releases all resources and resets the extractor to a clean state.
	 *
	 * Safe to call on an already-closed extractor (no-op). After returning,
	 * the extractor may be reused by calling open() again.
	 *
	 * Note: _data and _json_string are non-owning views into _buff, so they are
	 * simply reset to empty rather than freed.
	 */
	void extractor::close() {
		if (!_is_open) return;

		_buff.clear(); _buff.shrink_to_fit();	// release heap memory, not just logical size

		_data = {};				// span reset (no ownership to release)
		_json_string = {};		// string_view reset (no ownership to release)
		_metadata.clear();

		_is_open = false;
	}


	/**
	 * @brief Automatically opens the specified ASAR archive.
	 *
	 * Calls open(filepath) to correctly load the archive into memory.
	 *
	 * @param filepath	Path to the .asar file to open.
	 */
	extractor::extractor(const fs::path& filepath) {
		open(filepath);
	}


	/**
	 * @brief Destructor — ensures the archive is closed and resources freed.
	 *
	 * Calls close() inside a try/catch because destructors must not propagate
	 * exceptions. Any error during cleanup is silently swallowed; in practice
	 * close() only resets in-memory state and cannot fail.
	 */
	extractor::~extractor() {
		try {
			close();
		}
		catch (...) {

		}
	}

} // namespace asar