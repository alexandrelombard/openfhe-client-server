cmake_minimum_required(VERSION 3.23)
project(openfhe_client_server)

set(CMAKE_CXX_STANDARD 17)

include_directories(include/core include/pke include/third-party include/httpserver include/libmicrohttp)
link_directories(lib)

add_definitions(-DMATHBACKEND=4)

add_custom_target(copy_dll)

add_executable(openfhe_demo_simple_integers demo_simple_integers.cpp parser/ExpressionParser.cpp parser/ExpressionParser.h parser/ExpressionTreeNode.cpp parser/ExpressionTreeNode.h parser/ExpressionTree.cpp parser/ExpressionTree.h)
set_target_properties(openfhe_demo_simple_integers PROPERTIES DEPENDS copy_dll)
target_link_libraries(openfhe_demo_simple_integers benchmark OPENFHEcore OPENFHEpke OPENFHEbinfhe httpserver microhttpd -static-libstdc++)

add_executable(openfhe_demo_advanced_ckks_bootstraping demo_advanced_ckks_bootstraping.cpp parser/ExpressionParser.cpp parser/ExpressionParser.h parser/ExpressionTreeNode.cpp parser/ExpressionTreeNode.h parser/ExpressionTree.cpp parser/ExpressionTree.h)
set_target_properties(openfhe_demo_advanced_ckks_bootstraping PROPERTIES DEPENDS copy_dll)
target_link_libraries(openfhe_demo_advanced_ckks_bootstraping benchmark OPENFHEcore OPENFHEpke OPENFHEbinfhe httpserver microhttpd -static-libstdc++)

add_executable(openfhe_webserver web_server.cpp parser/ExpressionParser.cpp parser/ExpressionParser.h parser/ExpressionTreeNode.cpp parser/ExpressionTreeNode.h parser/ExpressionTree.cpp parser/ExpressionTree.h)
set_target_properties(openfhe_webserver PROPERTIES DEPENDS copy_dll)
target_link_libraries(openfhe_webserver benchmark OPENFHEcore OPENFHEpke OPENFHEbinfhe httpserver microhttpd -static-libstdc++)

#region Tests
add_executable(test_parser test/TestExpressionParser.cpp parser/ExpressionTree.h parser/ExpressionTree.cpp parser/ExpressionParser.h parser/ExpressionParser.cpp parser/ExpressionTreeNode.h parser/ExpressionTreeNode.cpp)
set_target_properties(test_parser PROPERTIES DEPENDS copy_dll)
target_link_libraries(test_parser benchmark OPENFHEcore OPENFHEpke OPENFHEbinfhe httpserver microhttpd -static-libstdc++)
#endregion

# Copy DLL files to build directory
add_custom_command(TARGET copy_dll POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/lib/libOPENFHEbinfhe.dll ${PROJECT_BINARY_DIR}/libOPENFHEbinfhe.dll)
add_custom_command(TARGET copy_dll POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/lib/libOPENFHEcore.dll ${PROJECT_BINARY_DIR}/libOPENFHEcore.dll)
add_custom_command(TARGET copy_dll POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/lib/libOPENFHEpke.dll ${PROJECT_BINARY_DIR}/libOPENFHEpke.dll)
add_custom_command(TARGET copy_dll POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/lib/libhttpserver-0.dll ${PROJECT_BINARY_DIR}/libhttpserver-0.dll)
add_custom_command(TARGET copy_dll POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/lib/libmicrohttpd-12.dll ${PROJECT_BINARY_DIR}/libmicrohttpd-12.dll)
add_custom_command(TARGET copy_dll POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/lib/libgnutls-30.dll ${PROJECT_BINARY_DIR}/libgnutls-30.dll)
add_custom_command(TARGET copy_dll POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/lib/libbrotlidec.dll ${PROJECT_BINARY_DIR}/libbrotlidec.dll)
add_custom_command(TARGET copy_dll POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/lib/libbrotlienc.dll ${PROJECT_BINARY_DIR}/libbrotlienc.dll)
add_custom_command(TARGET copy_dll POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/lib/libhogweed-6.dll ${PROJECT_BINARY_DIR}/libhogweed-6.dll)
add_custom_command(TARGET copy_dll POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/lib/libidn2-0.dll ${PROJECT_BINARY_DIR}/libidn2-0.dll)
add_custom_command(TARGET copy_dll POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/lib/libnettle-8.dll ${PROJECT_BINARY_DIR}/libnettle-8.dll)
add_custom_command(TARGET copy_dll POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/lib/libbrotlicommon.dll ${PROJECT_BINARY_DIR}/libbrotlicommon.dll)
add_custom_command(TARGET copy_dll POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/lib/libp11-kit-0.dll ${PROJECT_BINARY_DIR}/libp11-kit-0.dll)
add_custom_command(TARGET copy_dll POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/lib/libtasn1-6.dll ${PROJECT_BINARY_DIR}/libtasn1-6.dll)
add_custom_command(TARGET copy_dll POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/lib/libzstd.dll ${PROJECT_BINARY_DIR}/libzstd.dll)
add_custom_command(TARGET copy_dll POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/lib/libunistring-2.dll ${PROJECT_BINARY_DIR}/libunistring-2.dll)
add_custom_command(TARGET copy_dll POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/lib/libgmp-10.dll ${PROJECT_BINARY_DIR}/libgmp-10.dll)
add_custom_command(TARGET copy_dll POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/lib/libintl-8.dll ${PROJECT_BINARY_DIR}/libintl-8.dll)