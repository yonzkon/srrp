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
#include <cio/cio-stream.h>
#include "packet.h"
#include "router.h"
#include "connect.h"
#include "log.h"
#include "crc16.h"

#define UNIX_ADDR "unix://./test_unix"

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
    struct cio_stream *stream = cio_stream_connect(UNIX_ADDR);
    assert_true(stream);

    struct srrp_connect *conn = srrpc_new(stream, "3333");

    struct srrp_packet *pac = srrp_new_request("3333", "8888", "/hello", PAYLOAD);
    int rc = srrpc_send(conn, pac);
    assert_true(rc != -1);
    srrp_free(pac);

    for (;;) {
        if (requester_finished)
            break;

        assert_false(srrpc_check_fin(conn));

        if (srrpc_wait(conn, 100 * 1000) == 0)
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
    cio_stream_drop(stream);
    LOG_INFO("requester exit");
    return NULL;
}

/**
 * responser
 */

static int responser_finished = 0;

static void *responser_thread(void *args)
{
    struct cio_listener *listener = cio_listener_bind(UNIX_ADDR);
    assert_true(listener);

    struct srrp_router *router = srrpr_new();
    srrpr_add_listener(router, listener, "8888");

    for (;;) {
        if (responser_finished && requester_finished)
            break;

        for (;;) {
            struct cio_stream *stream = srrpr_check_fin(router);
            if (!stream) break;
            cio_stream_drop(stream);
        }

        if (srrpr_wait(router, 100 * 1000) == 0)
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
                        "{err:0,errmsg:'succ',data:{msg:'world'}}");
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
    cio_listener_drop(listener);
    LOG_INFO("responser exit");
    return NULL;
}

/**
 * test_req_resp
 */

static void test_req_resp(void **status)
{
    log_set_level(LOG_LV_TRACE);

    pthread_t responser_pid;
    pthread_create(&responser_pid, NULL, responser_thread, NULL);
    sleep(1);
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

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_req_resp),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
