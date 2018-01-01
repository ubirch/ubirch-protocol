add_executable(tests-basic
        TESTS/ubirch/basic/main.cpp
        )
target_link_libraries(tests-basic mbed-ubirch-protocol)
