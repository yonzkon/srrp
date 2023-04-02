#include <unistd.h>
#include <pthread.h>
#include <assert.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>

#include <cio-stream.h>
#include <srrp.h>
#include <srrp-router.h>
#include <srrp-log.h>
#include "opt.h"

static int exit_flag;

static void signal_handler(int sig)
{
    exit_flag = 1;
}

static struct opt opttab[] = {
    INIT_OPT_BOOL("-h", "help", false, "print this usage"),
    INIT_OPT_BOOL("-D", "debug", false, "enable debug [defaut: false]"),
    INIT_OPT_BOOL("-r", "srrp_mode", true, "enable srrp mode [defaut: true]"),
    INIT_OPT_STRING("-u:", "unix", "/tmp/apix", "unix socket addr"),
    INIT_OPT_STRING("-t:", "tcp", "127.0.0.1:3824", "tcp socket addr"),
    INIT_OPT_NONE(),
};

int main(int argc, char *argv[])
{
    opt_init_from_arg(opttab, argc, argv);
    signal(SIGINT, signal_handler);
    signal(SIGQUIT, signal_handler);

    struct opt *opt;
    opt = find_opt("debug", opttab);
    if (opt_bool(opt))
        log_set_level(LOG_LV_TRACE);

    opt = find_opt("unix", opttab);
    struct cio_listener *unix_listener = unix_listener_bind(opt_string(opt));
    if (!unix_listener) {
        perror("unix_listener_bind");
        exit(-1);
    }
    LOG_INFO("open unix socket #%d at %s", cio_listener_get_raw(unix_listener), opt_string(opt));

    opt = find_opt("tcp", opttab);
    struct cio_listener *tcp_listener = tcp_listener_bind(opt_string(opt));
    if (!tcp_listener) {
        perror("tcp_listener_bind");
        exit(-1);
    }
    LOG_INFO("open tcp socket #%d at %s", cio_listener_get_raw(tcp_listener), opt_string(opt));

    struct srrp_router *router = srrpr_new();
    srrpr_add_listener(router, unix_listener, 1, 0x1);
    srrpr_add_listener(router, tcp_listener, 1, 0x2);

    for (;;) {
        if (exit_flag == 1) break;

        if (srrpr_wait(router) == 0)
            continue;

        for (;;) {
            struct srrp_packet *pac = srrpr_iter(router);
            if (!pac) break;

            if (srrp_get_dstid(pac) == 0x1 || srrp_get_dstid(pac) == 0x2) {
                LOG_INFO("serv packet: %s", srrp_get_raw(pac));
                struct srrp_packet *resp = srrp_new_response(
                    srrp_get_dstid(pac),
                    srrp_get_srcid(pac),
                    srrp_get_anchor(pac),
                    "j:{\"err\":404,\"msg\":\"Service not found\"}");
                srrpr_send(router, resp);
                srrp_free(resp);
            } else {
                LOG_INFO("forward packet: %s", srrp_get_raw(pac));
                srrpr_forward(router, pac);
            }

        }
    }

    srrpr_drop(router); // auto close all fd
    return 0;
}
