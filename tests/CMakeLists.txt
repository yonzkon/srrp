include_directories(../src)

add_executable(test-srrp test-srrp.c)
target_link_libraries(test-srrp cmocka srrp cio pthread)
add_test(test-srrp ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test-srrp)

add_executable(test-req-resp test-req-resp.c)
target_link_libraries(test-req-resp cmocka srrp cio pthread)
add_test(test-req-resp ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test-req-resp)

add_executable(test-pub-sub test-pub-sub.c)
target_link_libraries(test-pub-sub cmocka srrp cio pthread)
add_test(test-pub-sub ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test-pub-sub)
