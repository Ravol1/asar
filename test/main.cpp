#include <iostream>
#include <fstream>

#include <nlohmann/json.hpp>


#include "asar.h"

namespace fs = std::filesystem;

const fs::path original_archive_name("app.asar");
const fs::path repacked_archive_name("rep.asar");

const fs::path extracted_path("extracted");


void test() {
	std::cout << "Opening original archive" << std::endl;
	asar::extractor original("app.asar");
	std::cout << "Extracting original" << std::endl;
	original.extract_all(extracted_path);
	original.close();

	std::cout << "Repacking" << std::endl;
	asar::packer repacked(extracted_path);
	std::cout << "Saving repacked archive" << std::endl;
	repacked.save(repacked_archive_name);
	repacked.close();
}


int main() {
	try {
		test();
	} catch (const std::exception& e) {
		std::cerr << e.what() << '\n';
		return EXIT_FAILURE;
	}

}