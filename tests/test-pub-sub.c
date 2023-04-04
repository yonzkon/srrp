#include <sched.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "srrp.h"
#include "srrp-router.h"
#include "srrp-connect.h"
#include "srrp-log.h"
#include "crc16.h"

#define UNIX_ADDR "./test_unix"
#define TCP_ADDR "127.0.0.1:1224"

/**
 * publish
 */

static int publish_finished = 0;

static void *publish_thread(void *args)
{
    int fd = socket(PF_INET, SOCK_STREAM, 0);
    if (fd == -1)
        return NULL;

    uint32_t host;
    uint16_t port;
    char *tmp = strdup(TCP_ADDR);
    char *colon = strchr(tmp, ':');
    *colon = 0;
    host = inet_addr(tmp);
    port = htons(atoi(colon + 1));
    free(tmp);

    int rc = 0;
    struct sockaddr_in sockaddr = {0};
    sockaddr.sin_family = PF_INET;
    sockaddr.sin_addr.s_addr = host;
    sockaddr.sin_port = port;

    rc = connect(fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr));
    if (rc == -1) {
        close(fd);
        return NULL;
    }

    sleep(1);

    struct srrp_packet *pac_sync = srrp_new_ctrl(0x9999, SRRP_CTRL_SYNC, "");
    send(fd, srrp_get_raw(pac_sync), srrp_get_packet_len(pac_sync), 0);
    srrp_free(pac_sync);

    struct srrp_packet *pac = srrp_new_publish("/test-topic", "{msg:'ahaa'}");
    rc = send(fd, srrp_get_raw(pac), srrp_get_packet_len(pac), 0);
    srrp_free(pac);

    sleep(1);

    close(fd);
    publish_finished = 1;
    LOG_INFO("publish exit");
    return NULL;
}

/**
 * subscribe
 */

static int subscribe_finished = 0;

static void *subscribe_thread(void *args)
{
    struct cio_stream *tcp_stream = tcp_stream_connect(TCP_ADDR);
    assert_true(tcp_stream);

    struct srrp_connect *conn = srrpc_new(tcp_stream, 1, 0x6666);

    struct srrp_packet *pac_sub = srrp_new_subscribe("/test-topic", "{}");
    int rc = srrpc_send(conn, pac_sub);
    assert_true(rc != -1);
    srrp_free(pac_sub);

    for (;;) {
        if (subscribe_finished)
            break;

        if (srrpc_wait(conn) == 0)
            continue;

        for (;;) {
            struct srrp_packet *pac = srrpc_iter(conn);
            if (!pac) break;
            if (srrp_get_leader(pac) == SRRP_PUBLISH_LEADER) {
                LOG_INFO("sub recv: %s", srrp_get_raw(pac));
                subscribe_finished = 1;
                break;
            }
        }
    }

    struct srrp_packet *pac_unsub = srrp_new_unsubscribe("/test-topic", "{}");
    rc = srrpc_send(conn, pac_unsub);
    assert_true(rc != -1);
    srrp_free(pac_unsub);

    sleep(1);

    srrpc_drop(conn);
    LOG_INFO("subscribe exit");
    return NULL;
}

/**
 * test_pub_sub
 */

static void test_pub_sub(void **status)
{
    log_set_level(LOG_LV_DEBUG);

    struct cio_listener *tcp_listener = tcp_listener_bind(TCP_ADDR);
    if (!tcp_listener) {
        perror("tcp_listener_bind");
        exit(-1);
    }

    struct srrp_router *router = srrpr_new();
    srrpr_add_listener(router, tcp_listener, 1, 0x1);

    pthread_t subscribe_pid;
    pthread_create(&subscribe_pid, NULL, subscribe_thread, NULL);
    pthread_t publish_pid;
    pthread_create(&publish_pid, NULL, publish_thread, NULL);

    for (;;) {
        if (publish_finished && subscribe_finished)
            break;

        if (srrpr_wait(router) == 0)
            continue;

        for (;;) {
            struct srrp_packet *pac = srrpr_iter(router);
            if (!pac) break;

            srrpr_forward(router, pac);
            LOG_INFO("forward packet: %s", srrp_get_raw(pac));
        }
    }

    pthread_join(publish_pid, NULL);
    pthread_join(subscribe_pid, NULL);

    srrpr_drop(router);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_pub_sub),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
