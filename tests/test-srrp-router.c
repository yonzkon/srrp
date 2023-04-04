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

const char *PAYLOAD = "t:hello";
const char *PAYLOAD2 =
    "t:0xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "2xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "3xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "4xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "5xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "6xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "7xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "8xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "9xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "0xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "2xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "3xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "4xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "5xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "6xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "7xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "8xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "9xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "0xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "2xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "3xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "4xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "5xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "6xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "7xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "8xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "9xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "0xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "2xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "3xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "4xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "5xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "6xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "7xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "8xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "9xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "0xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "2xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "3xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxo";

/**
 * requester
 */

static int requester_finished = 0;

static void *requester_thread(void *args)
{
    sleep(1);

    struct cio_stream *unix_stream = unix_stream_connect(UNIX_ADDR);
    assert_true(unix_stream);

   struct srrp_connect *conn = srrpc_new(unix_stream, 1, 0x3333);

    struct srrp_packet *pac = srrp_new_request(0x3333, 0x8888, "/hello", PAYLOAD);
    int rc = srrpc_send(conn, pac);
    assert_true(rc != -1);
    srrp_free(pac);

    for (;;) {
        if (requester_finished)
            break;

        if (srrpc_wait(conn) == 0)
            continue;

        for (;;) {
            struct srrp_packet *pac = srrpc_iter(conn);
            if (!pac) break;
            if (srrp_get_leader(pac) == SRRP_RESPONSE_LEADER) {
                LOG_INFO("requester on response: %s", srrp_get_raw(pac));
                requester_finished = 1;
                break;
            }
        }
    }

    sleep(1);

    srrpc_drop(conn);
    LOG_INFO("requester exit");
    return NULL;
}

/**
 * responser
 */

static int responser_finished = 0;

static void *responser_thread(void *args)
{
    struct cio_listener *unix_listener = unix_listener_bind(UNIX_ADDR);
    if (!unix_listener) {
        perror("unix_listener_bind");
        exit(-1);
    }

    struct srrp_router *router = srrpr_new();
    srrpr_add_listener(router, unix_listener, 1, 0x8888);

    for (;;) {
        if (responser_finished && requester_finished)
            break;

        if (srrpr_wait(router) == 0)
            continue;

        for (;;) {
            struct srrp_packet *pac = srrpr_iter(router);
            if (!pac) break;

            if (srrp_get_leader(pac) == SRRP_REQUEST_LEADER) {
                LOG_INFO("responser on request: %s", srrp_get_raw(pac));
                if (strstr(srrp_get_anchor(pac), "/hello") != 0) {
                    assert_true(strcmp((char *)srrp_get_payload(pac), PAYLOAD) == 0);
                    struct srrp_packet *resp = srrp_new_response(
                        srrp_get_dstid(pac), srrp_get_srcid(pac), srrp_get_anchor(pac),
                        "j:{err:0,errmsg:'succ',data:{msg:'world'}}");
                    srrpr_send(router, resp);
                    srrp_free(resp);
                    responser_finished = 1;
                    break;
                }
            } else if (srrp_get_leader(pac) == SRRP_RESPONSE_LEADER) {
                LOG_INFO("responser on response: %s", srrp_get_raw(pac));
            }
        }
    }

    sleep(1);

    srrpr_drop(router);
    LOG_INFO("responser exit");
    return NULL;
}

/**
 * test_api_request_response
 */

static void test_api_request_response(void **status)
{
    log_set_level(LOG_LV_TRACE);

    pthread_t responser_pid;
    pthread_create(&responser_pid, NULL, responser_thread, NULL);
    pthread_t requester_pid;
    pthread_create(&requester_pid, NULL, requester_thread, NULL);

    for (;;) {
        LOG_INFO("req state:%d, resp state:%d", requester_finished, responser_finished);
        if (requester_finished && responser_finished)
            break;
        else
            sleep(1);
    }

    pthread_join(requester_pid, NULL);
    pthread_join(responser_pid, NULL);
}

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
 * test_api_subscribe_publish
 */

static void test_api_subscribe_publish(void **status)
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
        cmocka_unit_test(test_api_request_response),
        cmocka_unit_test(test_api_subscribe_publish),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
