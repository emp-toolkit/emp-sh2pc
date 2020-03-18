# cmake_minimum_required (VERSION 2.8.11)
# project (emp-sh2pc)
# set(NAME "emp-sh2pc")

# find_path(CMAKE_FOLDER NAMES cmake/emp-tool-config.cmake)
# include(${CMAKE_FOLDER}/cmake/common.cmake)
# include(${CMAKE_FOLDER}/cmake/source_of_randomness.cmake)
# include(${CMAKE_FOLDER}/cmake/threading.cmake)

# find_package(emp-ot REQUIRED)
# include_directories(${EMP-OT_INCLUDE_DIRS})


# add_library(sha-256 SHARED test/sha-256.cpp)
# target_link_libraries(sha-256 ${EMP-OT_LIBRARIES})

# # find_library(CRYPTOPP_LIBRARIES NAMES cryptopp libcryptopp )
# # MESSAGE(STATUS "CryptoPP libs: " ${CRYPTOPP_LIBRARIES} )

# # target_link_libraries(sha256 ${CRYPTOPP_LIBRARIES})

# install(TARGETS sha-256 DESTINATION bin)


# # Installation
# install(FILES cmake/emp-sh2pc-config.cmake DESTINATION cmake/)
# install(DIRECTORY emp-sh2pc DESTINATION include/)


# # Test cases
# macro (add_test _name)
# 	add_test_with_lib(${_name} ${EMP-OT_LIBRARIES} sha-256)
# endmacro()

# # add_test (bit)
# #add_test (int)
# #add_test (float)
# #add_test (circuit_file)
# # add_test (example)
# #add_test (gc-sha)
# #add_test(update)
# #add_test(update_test)
# add_test(hmac)



# # add_test (sha256)




cmake_minimum_required (VERSION 2.8.11)
project (emp-sh2pc)
set(NAME "emp-sh2pc")

find_path(CMAKE_FOLDER NAMES cmake/emp-tool-config.cmake)
include(${CMAKE_FOLDER}/cmake/common.cmake)
include(${CMAKE_FOLDER}/cmake/source_of_randomness.cmake)
include(${CMAKE_FOLDER}/cmake/threading.cmake)

find_package(emp-ot REQUIRED)
include_directories(${EMP-OT_INCLUDE_DIRS})

# Installation
install(FILES cmake/emp-sh2pc-config.cmake DESTINATION cmake/)
install(DIRECTORY emp-sh2pc DESTINATION include/)

# Test cases
macro (add_test _name)
	add_test_with_lib(${_name} ${EMP-OT_LIBRARIES})
endmacro()

# add_test(hmac)
add_test(update)
# add_test (bit)
#add_test (int)
#add_test (float)
#add_test (circuit_file)
# add_test (example)
#add_test (gc-sha)
# add_test(update)
# add_test(update_test)