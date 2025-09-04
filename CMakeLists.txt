cmake_minimum_required(VERSION 3.16)
project(openvpn-manager VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_CXX_FLAGS_RELEASE "-O2 -march=native -DNDEBUG")
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -DDEBUG")

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

include_directories(include)

file(GLOB_RECURSE SOURCES
    "src/main.cpp"
    "src/main/dependency_factory.cpp"
    "src/domain/use_cases.cpp"
    "src/infrastructure/file_system_repository.cpp"
    "src/infrastructure/linux_implementations.cpp"
    "src/infrastructure/certificate_service.cpp"
    "src/infrastructure/linux_services.cpp"
    "src/presentation/cli_controller.cpp"
)

add_executable(${PROJECT_NAME} ${SOURCES})

target_compile_options(${PROJECT_NAME} PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Werror=return-type
)

install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION /usr/local/bin
)

add_custom_target(install-system
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target install
    COMMENT "installing openvpn-manager to system"
)

add_custom_target(uninstall
    COMMAND rm -f /usr/local/bin/openvpn-manager
    COMMENT "removing openvpn-manager from system"
)
