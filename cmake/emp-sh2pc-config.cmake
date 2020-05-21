find_package(emp-ot)

find_path(EMP-SH2PC_INCLUDE_DIR emp-sh2pc/emp-sh2pc.h)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(emp-sh2pc DEFAULT_MSG EMP-SH2PC_INCLUDE_DIR)

if(EMP-SH2PC_FOUND)
	set(EMP-SH2PC_INCLUDE_DIRS ${EMP-SH2PC_INCLUDE_DIR}/include/ ${EMP-OT_INCLUDE_DIRS})
	set(EMP-SH2PC_LIBRARIES ${EMP-TOOL_LIBRARIES})
endif()
