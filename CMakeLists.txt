cmake_minimum_required(VERSION 3.23)
project(openfhe_client_server)

set(CMAKE_CXX_STANDARD 17)

include_directories(include/core include/pke include/third-party include/httpserver include/libmicrohttp)
link_directories(lib)

add_definitions(-DMATHBACKEND=4)

add_executable(openfhe_client_server main.cpp)
target_link_libraries(openfhe_client_server benchmark OPENFHEcore OPENFHEpke OPENFHEbinfhe httpserver microhttpd)

# Copy DLL files to build directory
add_custom_command(TARGET openfhe_client_server POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/lib/libOPENFHEbinfhe.dll ${PROJECT_BINARY_DIR}/libOPENFHEbinfhe.dll)
add_custom_command(TARGET openfhe_client_server POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/lib/libOPENFHEcore.dll ${PROJECT_BINARY_DIR}/libOPENFHEcore.dll)
add_custom_command(TARGET openfhe_client_server POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/lib/libOPENFHEpke.dll ${PROJECT_BINARY_DIR}/libOPENFHEpke.dll)