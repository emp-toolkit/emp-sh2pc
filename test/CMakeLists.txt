# All tests now target the native SH2PCCtx (BooleanContext) layer, which is
# C++20. The garbled-backend tests run two-party via ${PROJECT_SOURCE_DIR}/run.
function(add_test_case name)
    add_executable(${name} ${name}.cpp)
    target_link_libraries(${name} PRIVATE emp-sh2pc::emp-sh2pc)
    target_compile_features(${name} PRIVATE cxx_std_20)
    set_target_properties(${name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
    add_test(NAME ${name}
             COMMAND ${name}
             WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
endfunction()

function(add_test_case_with_run name)
    add_executable(${name} ${name}.cpp)
    target_link_libraries(${name} PRIVATE emp-sh2pc::emp-sh2pc)
    target_compile_features(${name} PRIVATE cxx_std_20)
    set_target_properties(${name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
    add_test(NAME ${name}
             COMMAND ${PROJECT_SOURCE_DIR}/run $<TARGET_FILE:${name}>
             WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
endfunction()

add_test_case_with_run(test_bit)
add_test_case_with_run(test_int)
if(ENABLE_FLOAT)
    add_test_case_with_run(test_float)
endif()
add_test_case_with_run(test_example)
add_test_case_with_run(test_repeat)
add_test_case_with_run(test_aes)
add_test_case_with_run(test_context_sh2pc)
add_test_case_with_run(test_circuit_fn_sh2pc)
