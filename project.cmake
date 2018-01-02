add_executable(tests-basic
        TESTS/ubirch/basic/main.cpp
        )
target_link_libraries(tests-basic mbed-ubirch-protocol)

add_custom_target(run-tests
        COMMAND mbed test -v -n tests*
        WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR})

# Generate Documentation for firmware and board
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in")
    find_package(Doxygen)
    if (DOXYGEN_FOUND)
        configure_file(${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile @ONLY)
        add_custom_target(doc ALL
                ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
                WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
                COMMENT "Generating API documentation with Doxygen" VERBATIM
                )
        file(GLOB IMAGES ubirch-board-firmware/board/*/*.jpg)
        list(LENGTH IMAGES n)
        if (n GREATER 0)
            add_custom_command(TARGET doc
                    POST_BUILD
                    COMMAND ${CMAKE_COMMAND} -E copy ${IMAGES} ${CMAKE_CURRENT_BINARY_DIR}/docs/html
                    )
        endif ()
    endif (DOXYGEN_FOUND)
endif()