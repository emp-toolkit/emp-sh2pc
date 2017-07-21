cmake_minimum_required (VERSION 2.8.11)
project (emp-sh2pc)
set(NAME "emp-sh2pc")

if(POLICY CMP0042)
  cmake_policy(SET CMP0042 NEW) # use rpath on macOS
endif()

include_directories(${CMAKE_SOURCE_DIR})
include_directories(${CMAKE_SOURCE_DIR}/semihonest)

include_directories(${CMAKE_SOURCE_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin )
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} cmake/)
set(CMAKE_C_FLAGS "-pthread -Wall -march=native -O3 -maes")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -std=c++0x")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -pg -ggdb")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")

if(NOT CMAKE_BUILD_TYPE)
set(CMAKE_BUILD_TYPE Release)
endif(NOT CMAKE_BUILD_TYPE)
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

find_package(emp-ot)
INCLUDE_DIRECTORIES(${EMP-OT_INCLUDE_DIRS})


macro (add_test _name)
	add_executable("${_name}" "test/${_name}.cpp" ${basics})
	target_link_libraries("${_name}" ${EMP-OT_LIBRARIES}) 
endmacro()

install(FILES emp-sh2pc-config.cmake DESTINATION cmake/)
file(GLOB  headers 
"semihonest/*.h"
"emp-sh2pc"
)
install(FILES ${headers}  DESTINATION include/${NAME})

add_test (bit)
add_test (int)
add_test (float)
add_test (circuit_file)
add_test (example)
