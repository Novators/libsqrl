project(libsqrl)
set(PROJECT_NAME libsqrl)
cmake_minimum_required(VERSION 2.8)

# A hack...
if(CMAKE_MAJOR_VERSION EQUAL 3)
	cmake_policy(SET CMP0026 OLD)
	cmake_policy(SET CMP0045 OLD)
endif(CMAKE_MAJOR_VERSION EQUAL 3)
# End Hack.

include(ExternalProject)
include(${CMAKE_SOURCE_DIR}/cmake/find_sse.cmake)
#include(${CMAKE_SOURCE_DIR}/cmake/mergestaticlibs.cmake)
include(${CMAKE_SOURCE_DIR}/cmake/libutils.cmake)

set(sqrl_version_major 1)
set(sqrl_version_minor 1)
set(sqrl_build 17)
set(sqrl_version "${sqrl_version_major}.${sqrl_version_minor} build ${sqrl_build}")

#set(CMAKE_BUILD_TYPE Release)
set(CMAKE_BUILD_TYPE Debug)

set(CMAKE_C_FLAGS_DEBUG "-DDEBUG")

enable_testing()

set(SRCDIR ${CMAKE_SOURCE_DIR}/src)

if(CMAKE_COMPILER_IS_GNUCC)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden")
endif()

CHECK_FOR_SSE()

configure_file(${SRCDIR}/config.h.in ${SRCDIR}/config.h)
configure_file(sqrl_depends.c.in sqrl_depends.c)
configure_file(README.in README.md)

######################### MAC BUILD #########################
set(REQUIRED_LIBS_PRESENT TRUE)

ExternalProject_Add(libsodium
	PREFIX ${CMAKE_CURRENT_SOURCE_DIR}/libsodium
	#BINARY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libsodium/src/sodium
	BUILD_IN_SOURCE 1
	GIT_REPOSITORY https://github.com/jedisct1/libsodium.git
	UPDATE_COMMAND ""
	CONFIGURE_COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/scripts/sodium-conf.sh ${CMAKE_CURRENT_SOURCE_DIR}
	BUILD_COMMAND make -s
	INSTALL_COMMAND make -s install)
add_library(sodium STATIC IMPORTED)
SET_TARGET_PROPERTIES(sodium PROPERTIES IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/lib/libsodium.a)

find_library(RT_LIB NAMES rt)
if(NOT ${RT_LIB} STREQUAL "RT_LIB-NOTFOUND")
	set(LIBS ${LIBS} ${RT_LIB})
endif()

find_library(PTHREAD_LIB NAMES pthread)
if(NOT ${PTHREAD_LIB} STREQUAL "PTHREAD_LIB-NOTFOUND")
	set(LIBS ${LIBS} ${PTHREAD_LIB})
endif()

message("LIBS: ${LIBS}")

set(IMPORTED_LIBS sodium)

include_directories(include)

set(SRC src/user.c src/user_storage.c src/entropy/entropy.c src/entropy/rdrand.c 
	src/crypto/aes.c src/crypto/gcm.c src/encdec.c src/crypto/crypt.c src/util.c 
	src/storage.c src/block.c src/realtime.c src/url.c src/client.c)

add_library(tmpsqrl ${SRC})
add_dependencies(tmpsqrl libsodium)
target_link_libraries(tmpsqrl ${LIBS} ${IMPORTED_LIBS})

set(SLIBS tmpsqrl ${IMPORTED_LIBS} ${LIBS})

MERGE_STATIC_LIBS(sqrl sqrl "${SLIBS}")

if(REQUIRED_LIBS_PRESENT)
	add_executable(entropy src/cli/entropy_cli.c)
	target_link_libraries(entropy sqrl)
endif(REQUIRED_LIBS_PRESENT)

add_executable(enscrypt src/cli/enscrypt_bin.c)
target_link_libraries(enscrypt sqrl)

add_executable(makevectors src/cli/makevectors.c)
target_link_libraries(makevectors sqrl)

add_executable(gcm_test src/crypto/gcm.c src/crypto/aes.c src/test/gcmtest.c)

add_executable(storage_test src/test/storage_test.c)
target_link_libraries(storage_test sqrl)

add_executable(encdec_test src/test/encdec_test.c)
target_link_libraries(encdec_test sqrl)

add_executable(genrandom src/cli/genrandom.c)
target_link_libraries(genrandom sqrl)

add_executable(crypto_test src/test/crypto_test.c)
target_link_libraries(crypto_test sqrl)

add_executable(user_test src/test/user.c)
target_link_libraries(user_test sqrl)

add_executable(peek src/cli/peek.c)
target_link_libraries(peek sqrl)

add_executable(url_test src/test/url_test.c)
target_link_libraries(url_test sqrl)

#documentation
find_package(Doxygen QUIET)
if(DOXYGEN_FOUND)
	set(HEADERS src/sqrl_common.h src/sqrl_client.h src/sqrl_server.h)
	set(DOCSRC ${HEADERS} ${SRC} html/mainpage.dox)
	string(REPLACE ";" " " DOCSRCSTR "${DOCSRC}")
	configure_file(${CMAKE_SOURCE_DIR}/Doxyfile.in ${CMAKE_SOURCE_DIR}/Doxyfile)
	configure_file(${CMAKE_SOURCE_DIR}/html/mainpage.dox.in ${CMAKE_SOURCE_DIR}/html/mainpage.dox)

	add_custom_target(doc
		${DOXYGEN_EXECUTABLE} ${CMAKE_SOURCE_DIR}/Doxyfile
		WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
		COMMENT "Generating API documentation with Doxygen" VERBATIM
	)
endif(DOXYGEN_FOUND)

# Tests
include(CTest)
add_test(url_test url_test)
add_test(user_test user_test)
add_test(encdec_test encdec_test)
add_test(gcm_test gcm_test)
add_test(crypto_test crypto_test)
add_test(storage_test storage_test)
add_test(NAME sodium-test
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/libsodium/src/libsodium
	COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/scripts/makecheck.sh)

add_custom_target(check ${CMAKE_CTEST_COMMAND})
