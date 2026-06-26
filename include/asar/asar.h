#pragma once
#include <string>
#include <vector>
#include <filesystem>
#include <nlohmann/json.hpp>

#ifdef _WIN32
  #define ASAR __declspec(dllexport)
#else
  #define ASAR
#endif


using json = nlohmann::json;
namespace fs = std::filesystem;


namespace asar {

	/**
	 * @brief ASAR archive header structure.
	 *
	 * Represents the fixed binary header at the start of an ASAR file.
	 */
	struct AsarHeader
	{
		uint32_t signature;		// Magic number identifying ASAR archive, must be 0x04
		uint32_t pickle3;		// pickle2 + 4 (outer pickle size field).
		uint32_t pickle2;		// Size of embedded JSON metadata block rounded up to a 4-byte boundary, plus 4.
		uint32_t json_size;		// Size of embedded JSON metadata block.
	};


	/**
	 * @brief Integrity metadata
	 */
	struct IntegrityData {
		std::string final_hash;				// Hash of full data blob
		std::vector<std::string> blocks;	// Per-block hashes of the data blob for integrity checks
	};


	/**
	 * @brief Represents a file task during packing.
	 */
	struct FileTask {
		fs::path path;
		size_t size;
		size_t offset;
		json* node;
	};



	/**
	 * @brief ASAR archive extractor.
	 *
	 * Responsible for:
	 * - Opening and load ASAR files
	 * - Parsing metadata JSON
	 * - Providing access to raw and extracted file data
	 * - Extracting files from archive
	 */
	class ASAR extractor {
	public:
		[[nodiscard]]
		bool is_open() const { return _is_open; }

		std::span<const uint8_t> buff();		// Raw archive buffer: ASAR header + JSON header (metadata) + data
		std::string_view json_string() const;			// JSON metadata as string view
		std::span<const uint8_t> data() const;		// Binary data blob of archive
		json metadata();					// Parsed JSON metadata tree

		void open(const fs::path& filepath);
		void close();

		explicit extractor(const fs::path& filepath);
		extractor() = default;
		~extractor();

		extractor(const extractor&) = delete;
		extractor& operator=(const extractor&) = delete;

		// Move allowed for ownership transfer
		extractor(extractor&&) noexcept = default;

		const json* find_node(const std::filesystem::path& path);
		std::span<const uint8_t> get_file_data(const json* file_node);
		void extract_file(const json* file_node, const fs::path& path);
		void extract_all(const fs::path& dest = ".");

	private:
		bool _is_open = false;


		std::vector<uint8_t> _buff;				// Raw archive buffer: ASAR header + JSON header (metadata) + data
		std::string_view _json_string;			// JSON metadata as string view
		std::span<const uint8_t> _data;			// Binary data blob of archive
		json _metadata;							// Parsed JSON metadata tree

		void iterate_entries(const json* node, const fs::path& current_path);
	};




	/**
	 * @brief ASAR archive packer.
	 *
	 * Responsible for:
	 * - Walking a directory tree
	 * - Building ASAR JSON metadata
	 * - Packing file data into contiguous binary blob
	 */
	class ASAR packer {
	public:
		[[nodiscard]]
		bool is_open() const { return _is_open; }
		
		std::string_view json_string();		// JSON metadata serialized as string
		std::span<const uint8_t> data();	// Packed binary data buffer
		json metadata();					// Parsed metadata object

		void open(const fs::path& dir);
		void close();

		explicit packer(const fs::path& path) { open(path); };
		packer() = default;

		void save(const fs::path& path);


	private:
		bool _is_open = false;


		fs::path root;					// Root directory being packed
		uint64_t tot_offset = 0;		// Running offset in packed data

		json _metadata;					// Parsed metadata object


		AsarHeader header{};			// Constructed header for the output archive
		std::string _json_string;		// JSON metadata as string view
		std::vector<uint8_t> _data;		// Packed binary data buffer


		std::vector<FileTask> file_tasks;	// Queue of files to pack

		void construct_metadata(json* node, const fs::path& current_path);
		void construct_data();
	};
}



