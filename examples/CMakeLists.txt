include_directories(../src)

add_executable(srrpr srrpr.c opt.c)
target_link_libraries(srrpr srrp)

install(TARGETS srrpr
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    PUBLIC_HEADER DESTINATION include
)
