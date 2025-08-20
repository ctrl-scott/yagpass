cmake_minimum_required(VERSION 3.20)
project(passgen_sodium C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_executable(passgen_sodium
        src/menu.c
        src/vault.c
        src/passgen.c
)

# Try pkg-config first
find_package(PkgConfig QUIET)
if (PkgConfig_FOUND)
    pkg_check_modules(SODIUM QUIET libsodium)
endif()

if (SODIUM_FOUND)
    target_include_directories(passgen_sodium PRIVATE ${SODIUM_INCLUDE_DIRS})
    target_link_directories(passgen_sodium PRIVATE ${SODIUM_LIBRARY_DIRS})
    target_link_libraries(passgen_sodium PRIVATE ${SODIUM_LIBRARIES})
else()
    target_link_libraries(passgen_sodium PRIVATE sodium)
endif()
