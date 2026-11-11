# All tests target the SH2PCSession public handle over its SH2PCCtx gate context
# (BooleanContext), which is C++20. The garbled tests run two-party via
# ${PROJECT_SOURCE_DIR}/run; the concept gate is a single-process compile check.
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

# Two-party tests run under ./run, which takes the port from EMP_PORT. Each gets
# its own port, so `ctest -j` never runs two of them on one port. The ports
# start at 22000, below the range the OS assigns to outgoing connections (32768
# and up on Linux, 49152 and up on macOS), so no outgoing connection can hold a
# test's port.
set_property(GLOBAL PROPERTY EMP_SH2PC_TEST_NEXT_PORT 22000)
function(next_test_port out)
    get_property(port GLOBAL PROPERTY EMP_SH2PC_TEST_NEXT_PORT)
    math(EXPR next "${port} + 1")
    set_property(GLOBAL PROPERTY EMP_SH2PC_TEST_NEXT_PORT ${next})
    set(${out} ${port} PARENT_SCOPE)
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
    next_test_port(port)
    set_tests_properties(${name} PROPERTIES ENVIRONMENT "EMP_PORT=${port}")
endfunction()

add_test_case_with_run(test_bit)
add_test_case_with_run(test_int)
if(ENABLE_FLOAT)
    add_test_case_with_run(test_float)
endif()
add_test_case_with_run(test_example)
add_test_case_with_run(test_repeat)
add_test_case_with_run(test_aes)
add_test_case_with_run(test_ot)
add_test_case_with_run(test_context_sh2pc)
add_test_case_with_run(test_circuit_fn_sh2pc)
add_test_case(test_session_concepts_sh2pc)
