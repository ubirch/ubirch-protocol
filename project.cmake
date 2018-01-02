add_executable(tests-basic
        TESTS/ubirch/basic/main.cpp
        )
target_link_libraries(tests-basic mbed-ubirch-protocol)

add_custom_target(run-tests
        COMMAND mbed test -v -n tests*
        WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR})