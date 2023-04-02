include_directories(../src)

add_executable(test-srrp test_srrp.c)
target_link_libraries(test-srrp cmocka apix)
add_test(test-srrp ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test-srrp)
