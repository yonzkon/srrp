#include <unistd.h>
#include <pthread.h>
#include <assert.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>

#include <cio/cio-stream.h>
#include "packet.h"
#include "router.h"
#include "log.h"
#include "opt.h"

static int exit_flag;

static void signal_handler(int sig)
{
    (void)sig;
    exit_flag = 1;
}

static struct opt opttab[] = {
    INIT_OPT_BOOL("-h", "help", false, "print this usage"),
    INIT_OPT_BOOL("-d", "debug", false, "enable debug [defaut: false]"),
    INIT_OPT_BOOL("-D", "trace", false, "enable trace [defaut: false]"),
    INIT_OPT_BOOL("-r", "srrp_mode", true, "enable srrp mode [defaut: true]"),
    INIT_OPT_STRING("-u:", "unix", "unix:///tmp/srrp", "unix socket addr"),
    INIT_OPT_STRING("-t:", "tcp", "tcp://127.0.0.1:3824", "tcp socket addr"),
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
        log_set_level(LOG_LV_DEBUG);
    opt = find_opt("trace", opttab);
    if (opt_bool(opt))
        log_set_level(LOG_LV_TRACE);

    opt = find_opt("unix", opttab);
    struct cio_listener *unix_listener = cio_listener_bind(opt_string(opt));
    if (!unix_listener) {
        perror("unix_listener_bind");
        exit(-1);
    }
    LOG_INFO("open unix socket #%d at %s",
             cio_listener_getfd(unix_listener), opt_string(opt));

    opt = find_opt("tcp", opttab);
    struct cio_listener *tcp_listener = cio_listener_bind(opt_string(opt));
    if (!tcp_listener) {
        perror("tcp_listener_bind");
        exit(-1);
    }
    LOG_INFO("open tcp socket #%d at %s",
             cio_listener_getfd(tcp_listener), opt_string(opt));

    struct srrp_router *router = srrpr_new();
    srrpr_add_listener(router, unix_listener, "router-unix");
    srrpr_add_listener(router, tcp_listener, "router-tcp");

    for (;;) {
        if (exit_flag == 1) break;

        for (;;) {
            struct cio_stream *stream = srrpr_check_fin(router);
            if (!stream) break;
            LOG_INFO("close socket #%d", cio_stream_getfd(stream));
        }

        for (;;) {
            struct cio_stream *stream = srrpr_check_accept(router);
            if (!stream) break;
            LOG_INFO("accept socket #%d", cio_stream_getfd(stream));
        }

        if (srrpr_wait(router, 10 * 1000) == 0) {
            continue;
        }

        struct srrp_packet *pac;
        while ((pac = srrpr_iter(router))) {
            if (strcmp(srrp_get_dstid(pac), "router-unix") != 0 &&
                strcmp(srrp_get_dstid(pac), "router-tcp") != 0) {
                srrpr_forward(router, pac);
                LOG_DEBUG("forward packet: %s", srrp_get_raw(pac));
            }
        }
    }

    srrpr_drop(router); // auto close all fd
    cio_listener_drop(unix_listener);
    cio_listener_drop(tcp_listener);
    return 0;
}
