cmake_minimum_required (VERSION 2.8.11)
project (emp-sh2pc)
set(NAME "emp-sh2pc")

find_path(CMAKE_FOLDER NAMES cmake/emp-tool-config.cmake)
include(${CMAKE_FOLDER}/cmake/common.cmake)
include(${CMAKE_FOLDER}/cmake/enable_rdseed.cmake)
include(${CMAKE_FOLDER}/cmake/enable_float.cmake)

find_package(emp-ot REQUIRED)
include_directories(${EMP-OT_INCLUDE_DIRS})

# Installation
install(FILES cmake/emp-sh2pc-config.cmake DESTINATION cmake/)
install(DIRECTORY emp-sh2pc DESTINATION include/)

# Test cases
macro (add_test _name)
	add_test_with_lib(${_name} ${EMP-OT_LIBRARIES})
endmacro()

add_test (bit)
add_test (int)
IF(${ENABLE_FLOAT})
add_test (float)
ENDIF(${ENABLE_FLOAT})
add_test (circuit_file)
add_test (example)
add_test (repeat)
