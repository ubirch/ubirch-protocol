add_executable(tests-basic
        TESTS/ubirch/plain/main.cpp
        TESTS/ubirch/signed/main.cpp
        TESTS/ubirch/chained/main.cpp
        TESTS/ubirch/kex/main.cpp
        )
target_link_libraries(tests-basic mbed-ubirch-protocol)

add_custom_target(run-tests
        COMMAND mbed test -v -n tests-ubirch* --profile ${MBED_BUILD_PROFILE}
        WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR})

add_custom_target(run-tests-for-deps
        COMMAND mbed test -n ubirch\\* --profile ${MBED_BUILD_PROFILE}
        WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR})