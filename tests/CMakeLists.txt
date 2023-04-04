include_directories(../src)

add_executable(test-srrp test-srrp.c)
target_link_libraries(test-srrp cmocka srrp cio)
add_test(test-srrp ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test-srrp)

add_executable(test-srrp-router test-srrp-router.c)
target_link_libraries(test-srrp-router cmocka srrp cio)
add_test(test-srrp-router ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test-srrp-router)
