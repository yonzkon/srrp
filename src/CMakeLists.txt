file(GLOB SRC *.c)
file(GLOB INC srrp.h srrp-types.h srrp-router.h srrp-log.h)

if (BUILD_STATIC)
    add_library(srrp-static STATIC ${SRC} ${SRC_POSIX})
    set_target_properties(srrp-static PROPERTIES OUTPUT_NAME srrp)
    set_target_properties(srrp-static PROPERTIES PUBLIC_HEADER "${INC}")
    set(TARGET_STATIC srrp-static)
endif ()

if (BUILD_SHARED)
    add_library(srrp SHARED ${SRC} ${SRC_POSIX})
    set_target_properties(srrp PROPERTIES PUBLIC_HEADER "${INC}")
    set_target_properties(srrp PROPERTIES VERSION 0.0.1 SOVERSION 0)
    set(TARGET_SHARED srrp)
endif ()

install(TARGETS ${TARGET_STATIC} ${TARGET_SHARED}
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    PUBLIC_HEADER DESTINATION include
)
