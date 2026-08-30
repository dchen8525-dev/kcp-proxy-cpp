set(_configs "")
if(DEFINED CTEST_CONFIGURATION_TYPE AND NOT CTEST_CONFIGURATION_TYPE STREQUAL "")
    list(APPEND _configs "${CTEST_CONFIGURATION_TYPE}")
endif()
list(APPEND _configs Release Debug RelWithDebInfo MinSizeRel)

set(_test_exe "")
foreach(_config IN LISTS _configs)
    set(_candidate "${TEST_BINARY_DIR}/${_config}/kcp_proxy_test.exe")
    if(EXISTS "${_candidate}")
        set(_test_exe "${_candidate}")
        break()
    endif()
endforeach()

if(_test_exe STREQUAL "")
    set(_candidate "${TEST_BINARY_DIR}/kcp_proxy_test")
    if(EXISTS "${_candidate}")
        set(_test_exe "${_candidate}")
    endif()
endif()

if(_test_exe STREQUAL "")
    message(FATAL_ERROR "kcp_proxy_test executable was not found under ${TEST_BINARY_DIR}")
endif()

execute_process(
    COMMAND "${_test_exe}"
    RESULT_VARIABLE _result
)
if(NOT _result EQUAL 0)
    message(FATAL_ERROR "kcp_proxy_tests failed with exit code ${_result}")
endif()
