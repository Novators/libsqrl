project(curve25519-donna)
cmake_minimum_required(VERSION 2.8)

include(${CMAKE_SOURCE_DIR}/../../../cmake/find_sse.cmake)

#set(CMAKE_BUILD_TYPE Release)
set(CMAKE_BUILD_TYPE Debug)

#Test for 64 bit systems
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  set(SRC ${SRC} curve25519-donna-c64.c)
else(CMAKE_SIZEOF_VOID_P EQUAL 8)
  set(SRC ${SRC} curve25519-donna.c)
endif(CMAKE_SIZEOF_VOID_P EQUAL 8)

add_library(curve25519 STATIC ${SRC})
add_executable(curve25519-test ${SRC} test-curve25519.c)

install(TARGETS curve25519
			LIBRARY DESTINATION lib 
			ARCHIVE DESTINATION lib
			RUNTIME DESTINATION bin)

# Tests
enable_testing()
add_test(curve25519-test curve25519-test)
