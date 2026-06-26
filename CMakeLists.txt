cmake_minimum_required(VERSION 3.20)
project(asar)

set(CMAKE_CXX_STANDARD 23)

option(ASAR_BUILD_SHARED "Build as shared library" ON)
option(ASAR_BUILD_TESTS "Build test executable" OFF)


find_package(OpenSSL REQUIRED)

list(APPEND ASAR_SRC
        src/asar_extractor.cpp
        src/asar_packer.cpp
)


if(ASAR_BUILD_SHARED)
    add_library(asar SHARED ${ASAR_SRC})
    target_compile_definitions(asar PRIVATE ASAR_BUILD_DLL)
else()
    add_library(asar STATIC ${ASAR_SRC})
endif()

target_link_libraries(asar
        PRIVATE
        OpenSSL::Crypto
)

target_include_directories(asar
        PUBLIC include/asar
)


if(ASAR_BUILD_TESTS)
    add_executable(asar_test
            test/main.cpp
            src/asar_packer.cpp
            src/asar_extractor.cpp
    )

    target_link_libraries(asar_test PRIVATE asar OpenSSL::Crypto)
endif()




