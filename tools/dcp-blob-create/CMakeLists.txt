cmake_minimum_required(VERSION 3.0)

project(dcp-blob-create C)

find_library(KCAPI_LIBRARY kcapi)
find_path(KCAPI_INCLUDE_DIR kcapi.h)

if(NOT KCAPI_LIBRARY OR NOT KCAPI_INCLUDE_DIR)
	message(FATAL_ERROR "libkcapi not found (need libkcapi-dev / libkcapi)")
endif()

add_executable(dcp-blob-create dcp-blob-create.c)
target_include_directories(dcp-blob-create PRIVATE ${KCAPI_INCLUDE_DIR})
target_link_libraries(dcp-blob-create ${KCAPI_LIBRARY})

install(TARGETS dcp-blob-create DESTINATION ${CMAKE_INSTALL_BINDIR})
