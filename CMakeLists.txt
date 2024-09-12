cmake_minimum_required(VERSION 3.28)
project(vault_client)

set(CMAKE_CXX_STANDARD 17)
set(LIB_CURL /opt/homebrew/Cellar/curl/8.9.1)
set(LIB_JSON /opt/homebrew/Cellar/jsoncpp/1.9.5)

add_executable(vault_client main.cpp
        ob_encrypt_kms.h
        ob_encrypt_kms.cpp
        ob_errno.h
        ob_macro_utils.h
        ob_dlist.h
)

target_include_directories(vault_client PUBLIC ${LIB_CURL}/include)
target_link_libraries(vault_client ${LIB_CURL}/lib/libcurl.dylib)

target_include_directories(vault_client PUBLIC ${LIB_JSON}/include)
target_link_libraries(vault_client ${LIB_JSON}/lib/libjsoncpp.dylib)
