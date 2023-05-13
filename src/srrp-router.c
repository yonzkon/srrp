#include "srrp-router.h"
#include <sys/time.h>
#include <assert.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <regex.h>
#include <cio.h>
#include <cio-stream.h>
#include "srrp.h"
#include "srrp-types.h"
#include "srrp-log.h"
#include "list.h"
#include "vec.h"
#include "str.h"

#define STREAM_SYNC_TIMEOUT (1000 * 5) /*ms*/
#define PARSE_PACKET_TIMEOUT 1000 /*ms*/
#define PAYLOAD_LIMIT 1400
#define WAIT_TIMEOUT (10 * 1000)

#define TOKEN_LISTENER 1
#define TOKEN_STREAM 2

enum message_state {
    MESSAGE_ST_NONE = 0,
    MESSAGE_ST_WAITING,
    MESSAGE_ST_PENDING,
    MESSAGE_ST_FINISHED,
    MESSAGE_ST_FORWARD,
};

struct message {
    int state;
    struct srrp_stream *stream; /* receive from */
    struct srrp_stream *forward; /* forward to */
    struct srrp_packet *pac;
    struct list_head ln;
};

enum srrp_stream_state {
    SRRP_STREAM_ST_NONE = 0,
    SRRP_STREAM_ST_NODEID_NORMAL,
    SRRP_STREAM_ST_NODEID_DUP,
    SRRP_STREAM_ST_NODEID_ZERO,
    SRRP_STREAM_ST_FINISHED,
};

struct srrp_stream {
    int state; /* srrp_stream_state */

    time_t ts_sync_in;
    time_t ts_sync_out;
    struct timeval ts_recv;

    vec_8_t *txbuf;
    vec_8_t *rxbuf;

    str_t *l_nodeid; /* local nodeid */
    str_t *r_nodeid; /* remote nodeid */
    vec_p_t *sub_topics;
    struct srrp_packet *rxpac_unfin;

    struct cio_stream *stream;
    int owned;

    struct list_head ln;
    struct srrp_router *router;
};

struct srrp_listener {
    str_t *l_nodeid; /* local nodeid */
    struct cio_listener *listener;
    int owned;
    struct list_head ln;
    struct srrp_router *router;
};

struct srrp_router {
    struct cio *ctx;
    struct list_head listeners;
    struct list_head streams;
    struct list_head msgs;
};

/**
 * message
 */

static void message_forward(struct message *msg)
{
    msg->state = MESSAGE_ST_FORWARD;
}

static void message_pending(struct message *msg)
{
    msg->state = MESSAGE_ST_PENDING;
}

static void message_finish(struct message *msg)
{
    msg->state = MESSAGE_ST_FINISHED;
}

static int message_is_finished(struct message *msg)
{
    return msg->state == MESSAGE_ST_FINISHED;
}

static void message_drop(struct message *msg)
{
    list_del(&msg->ln);
    srrp_free(msg->pac);
    free(msg);
}

/**
 * srrp_stream
 */

static struct srrp_stream *srrp_stream_new(
    struct srrp_router *router, struct cio_stream *stream,
    int owned, const char *l_nodeid)
{
    struct srrp_stream *ss = malloc(sizeof(*ss));
    memset(ss, 0, sizeof(*ss));

    ss->ts_sync_in = 0;
    ss->ts_sync_out = 0;

    ss->txbuf = vec_new(1, 2048);
    ss->rxbuf = vec_new(1, 2048);

    ss->l_nodeid = str_new(l_nodeid);
    ss->r_nodeid = str_new("");
    ss->sub_topics = vec_new(sizeof(void *), 3);
    ss->rxpac_unfin = NULL;

    ss->stream = stream;
    ss->owned = owned;
    INIT_LIST_HEAD(&ss->ln);
    ss->router = router;
    return ss;
}

static void srrp_stream_drop(struct srrp_stream *ss)
{
    vec_free(ss->txbuf);
    vec_free(ss->rxbuf);

    str_free(ss->l_nodeid);
    str_free(ss->r_nodeid);

    while (vsize(ss->sub_topics)) {
        str_t *tmp = 0;
        vpop(ss->sub_topics, &tmp);
        str_free(tmp);
    }
    vec_free(ss->sub_topics);

    if (ss->owned) {
        cio_stream_drop(ss->stream);
    }

    list_del(&ss->ln);
    free(ss);
}

static void srrp_stream_sync_nodeid(struct srrp_stream *ss)
{
    LOG_TRACE("[%p:sync_nodeid] #%d sync", ss->router, cio_stream_get_fd(ss->stream));

    struct srrp_packet *pac = srrp_new_ctrl(sget(ss->l_nodeid), SRRP_CTRL_SYNC, "");
    cio_stream_send(ss->stream, srrp_get_raw(pac), srrp_get_packet_len(pac));
    srrp_free(pac);
    ss->ts_sync_out = time(0);
}

static void log_hex_string(const char *buf, u32 len)
{
    printf("len: %d, data: ", (int)len);
    for (int i = 0; i < (int)len; i++) {
        if (isprint(buf[i]))
            printf("%c", buf[i]);
        else
            printf("_0x%.2x", buf[i]);
    }
    printf("\n");
}

static void srrp_stream_parse_packet(struct srrp_stream *ss)
{
    while (vsize(ss->rxbuf)) {
        u32 offset = srrp_next_packet_offset(
            vraw(ss->rxbuf), vsize(ss->rxbuf));
        if (offset != 0) {
            LOG_WARN("[%p:parse_packet] broken packet:", ss->router);
            log_hex_string(vraw(ss->rxbuf), offset);
            vdrop(ss->rxbuf, offset);
        }
        if (vsize(ss->rxbuf) == 0)
            break;

        struct srrp_packet *pac = srrp_parse(
            vraw(ss->rxbuf), vsize(ss->rxbuf));
        if (pac == NULL) {
            struct timeval now;
            gettimeofday(&now, NULL);
            if (now.tv_sec * 1000 * 1000 + now.tv_usec <
                ss->ts_recv.tv_sec * 1000 * 1000 +
                ss->ts_recv.tv_usec +
                PARSE_PACKET_TIMEOUT * 1000)
                break;

            LOG_ERROR("[%p:parse_packet] wrong packet:%s",
                      ss->router, vraw(ss->rxbuf));
            u32 offset = srrp_next_packet_offset(
                vraw(ss->rxbuf) + 1,
                vsize(ss->rxbuf) - 1) + 1;
            vdrop(ss->rxbuf, offset);
            break;
        }
        vdrop(ss->rxbuf, srrp_get_packet_len(pac));
        assert(srrp_get_ver(pac) == SRRP_VERSION);

        // concatenate srrp packet
        if (ss->rxpac_unfin) {
            assert(srrp_get_fin(ss->rxpac_unfin) == SRRP_FIN_0);
            if (srrp_get_leader(pac) != srrp_get_leader(ss->rxpac_unfin) ||
                srrp_get_ver(pac) != srrp_get_ver(ss->rxpac_unfin) ||
                strcmp(srrp_get_srcid(pac), srrp_get_srcid(ss->rxpac_unfin)) != 0 ||
                strcmp(srrp_get_dstid(pac), srrp_get_dstid(ss->rxpac_unfin)) != 0 ||
                strcmp(srrp_get_anchor(pac), srrp_get_anchor(ss->rxpac_unfin)) != 0) {
                // drop pre pac
                srrp_free(ss->rxpac_unfin);
                // set to rxpac_unfin
                ss->rxpac_unfin = pac;
            } else {
                struct srrp_packet *tsp = ss->rxpac_unfin;
                ss->rxpac_unfin = srrp_cat(tsp, pac);
                assert(ss->rxpac_unfin != NULL);
                srrp_free(tsp);
                srrp_free(pac);
                pac = NULL;
            }
        } else {
            ss->rxpac_unfin = pac;
            pac = NULL;
        }

        LOG_TRACE("[%p:parse_packet] right packet:%s",
                  ss->router, srrp_get_raw(ss->rxpac_unfin));

        // construct message if receviced fin srrp packet
        if (srrp_get_fin(ss->rxpac_unfin) == SRRP_FIN_1) {
            struct message *msg = malloc(sizeof(*msg));
            memset(msg, 0, sizeof(*msg));
            msg->state = MESSAGE_ST_NONE;
            msg->stream = ss;
            msg->pac = ss->rxpac_unfin;
            INIT_LIST_HEAD(&msg->ln);
            list_add_tail(&msg->ln, &ss->router->msgs);

            ss->rxpac_unfin = NULL;
        }
    }
}

static void srrp_stream_send(
    struct srrp_stream *ss, const struct srrp_packet *pac)
{
    u32 idx = 0;
    struct srrp_packet *tmp_pac = NULL;

    LOG_TRACE("[%p:srrp_stream_send] send:%s", ss->router, srrp_get_raw(pac));

    // payload_len < cnt, maybe zero, should not remove this code
    if (srrp_get_payload_len(pac) < PAYLOAD_LIMIT) {
        vpack(ss->txbuf, srrp_get_raw(pac), srrp_get_packet_len(pac));
        cio_register(ss->router->ctx, cio_stream_get_fd(ss->stream),
                     TOKEN_STREAM, CIOF_READABLE | CIOF_WRITABLE, ss);
        return;
    }

    // payload_len > cnt, can't be zero
    while (idx != srrp_get_payload_len(pac)) {
        u32 tmp_cnt = srrp_get_payload_len(pac) - idx;
        u8 fin = 0;
        if (tmp_cnt > PAYLOAD_LIMIT) {
            tmp_cnt = PAYLOAD_LIMIT;
            fin = SRRP_FIN_0;
        } else {
            fin = SRRP_FIN_1;
        };
        tmp_pac = srrp_new(srrp_get_leader(pac),
                       fin,
                       srrp_get_srcid(pac),
                       srrp_get_dstid(pac),
                       srrp_get_anchor(pac),
                       srrp_get_payload(pac) + idx,
                       tmp_cnt);
        LOG_TRACE("[%p:srrp_stream_send] split:%s", ss->router, srrp_get_raw(tmp_pac));
        vpack(ss->txbuf, srrp_get_raw(tmp_pac), srrp_get_packet_len(tmp_pac));
        idx += tmp_cnt;
        srrp_free(tmp_pac);
    }
    cio_register(ss->router->ctx, cio_stream_get_fd(ss->stream),
                 TOKEN_STREAM, CIOF_READABLE | CIOF_WRITABLE, ss);
}

static void srrp_stream_send_response(
    struct srrp_stream *ss, struct srrp_packet *req, const char *payload)
{
    struct srrp_packet *resp = srrp_new_response(
        srrp_get_dstid(req),
        srrp_get_srcid(req),
        srrp_get_anchor(req),
        payload);
    srrp_stream_send(ss, resp);
    srrp_free(resp);
}

/**
 * srrp_listener
 */

static struct srrp_listener *srrp_listener_new(
    struct srrp_router *router, struct cio_listener *listener,
    int owned, const char *l_nodeid)
{
    struct srrp_listener *sl = malloc(sizeof(*sl));
    memset(sl, 0, sizeof(*sl));

    sl->l_nodeid = str_new(l_nodeid);
    sl->listener = listener;
    sl->owned = owned;
    INIT_LIST_HEAD(&sl->ln);
    sl->router = router;
    return sl;
}

static void srrp_listener_drop(struct srrp_listener *sl)
{
    str_free(sl->l_nodeid);

    if (sl->owned) {
        cio_listener_drop(sl->listener);
    }

    list_del(&sl->ln);
    free(sl);
}

/**
 * srrp_router
 */

struct srrp_router *srrpr_new()
{
    struct srrp_router *router = malloc(sizeof(*router));
    assert(router);
    memset(router, 0, sizeof(*router));

    router->ctx = cio_new();
    INIT_LIST_HEAD(&router->listeners);
    INIT_LIST_HEAD(&router->streams);
    INIT_LIST_HEAD(&router->msgs);

    return router;
}

void srrpr_drop(struct srrp_router *router)
{
    cio_drop(router->ctx);

    struct srrp_listener *sl, *n_sl;
    list_for_each_entry_safe(sl, n_sl, &router->listeners, ln) {
        if (sl->owned)
            srrp_listener_drop(sl);
    }

    struct srrp_stream *ss, *n_ss;
    list_for_each_entry_safe(ss, n_ss, &router->streams, ln) {
        if (ss->owned)
            srrp_stream_drop(ss);
    }

    struct message *msg, *n_msg;
    list_for_each_entry_safe(msg, n_msg, &router->msgs, ln) {
        message_drop(msg);
    }

    free(router);
}

void srrpr_add_listener(
    struct srrp_router *router, struct cio_listener *listener,
    int owned, const char *nodeid)
{
    struct srrp_listener *sl = srrp_listener_new(router, listener, owned, nodeid);
    cio_register(router->ctx, cio_listener_get_fd(listener),
                 TOKEN_LISTENER, CIOF_READABLE, sl);
    list_add(&sl->ln, &router->listeners);
}

void srrpr_add_stream(
    struct srrp_router *router, struct cio_stream *stream,
    int owned, const char *nodeid)
{
    struct srrp_stream *ss = srrp_stream_new(router, stream, owned, nodeid);
    cio_register(router->ctx, cio_stream_get_fd(stream),
                 TOKEN_STREAM, CIOF_READABLE, ss);
    list_add(&ss->ln, &router->streams);
}

static struct srrp_stream *
srrpr_find_stream_by_l_nodeid(struct srrp_router *router, const char *nodeid)
{
    if (nodeid == NULL) return NULL;

    char tmp[SRRP_ID_MAX] = {0};
    sscanf(nodeid, "%255[^@]", tmp);

    struct srrp_stream *pos, *n;
    list_for_each_entry_safe(pos, n, &router->streams, ln) {
        if (strcmp(sget(pos->l_nodeid), tmp) == 0)
            return pos;
    }
    return NULL;
}

static struct srrp_stream *
srrpr_find_stream_by_r_nodeid(struct srrp_router *router, const char *nodeid)
{
    if (nodeid == NULL) return NULL;

    char tmp[SRRP_ID_MAX] = {0};
    sscanf(nodeid, "%255[^@]", tmp);

    struct srrp_stream *pos, *n;
    list_for_each_entry_safe(pos, n, &router->streams, ln) {
        if (strcmp(sget(pos->r_nodeid), tmp) == 0)
            return pos;
    }
    return NULL;
}

static struct srrp_stream *
srrpr_find_stream_by_nodeid(struct srrp_router *router, const char *nodeid)
{
    if (nodeid == NULL) return NULL;

    char tmp[SRRP_ID_MAX] = {0};
    sscanf(nodeid, "%255[^@]", tmp);

    struct srrp_stream *pos, *n;
    list_for_each_entry_safe(pos, n, &router->streams, ln) {
        if (strcmp(sget(pos->l_nodeid), tmp) == 0 ||
            strcmp(sget(pos->r_nodeid), tmp) == 0)
            return pos;
    }
    return NULL;
}

static void
handle_ctrl(struct message *msg)
{
    struct srrp_stream *tmp = srrpr_find_stream_by_nodeid(
        msg->stream->router, srrp_get_srcid(msg->pac));
    if (tmp != NULL && tmp != msg->stream) {
        struct srrp_packet *pac = srrp_new_ctrl(
            sget(msg->stream->l_nodeid), SRRP_CTRL_NODEID_DUP, "");
        srrp_stream_send(msg->stream, pac);
        srrp_free(pac);
        msg->stream->state = SRRP_STREAM_ST_NODEID_DUP;
        goto out;
    }

    if (strcmp(srrp_get_anchor(msg->pac), SRRP_CTRL_SYNC) == 0) {
        str_free(msg->stream->r_nodeid);
        msg->stream->r_nodeid = str_new(srrp_get_srcid(msg->pac));
        msg->stream->state = SRRP_STREAM_ST_NODEID_NORMAL;
        msg->stream->ts_sync_in = time(0);
        goto out;
    }

    if (strcmp(srrp_get_anchor(msg->pac), SRRP_CTRL_NODEID_DUP) == 0) {
        LOG_WARN("[%p:handle_ctrl] recv nodeid dup:%s",
                 msg->stream->router, srrp_get_raw(msg->pac));
        goto out;
    }

out:
    message_finish(msg);
}

static void
handle_subscribe(struct message *msg)
{
    for (u32 i = 0; i < vsize(msg->stream->sub_topics); i++) {
        if (strcmp(sget(vat(msg->stream->sub_topics, i)), srrp_get_anchor(msg->pac)) == 0) {
            // TODO: do what?
            message_finish(msg);
            return;
        }
    }

    str_t *topic = str_new(srrp_get_anchor(msg->pac));
    vpush(msg->stream->sub_topics, &topic);

    struct srrp_packet *pub = srrp_new_publish(
        srrp_get_anchor(msg->pac), "{\"state\":\"sub\"}");
    srrp_stream_send(msg->stream, pub);
    srrp_free(pub);

    message_finish(msg);
}

static void
handle_unsubscribe(struct message *msg)
{
    for (u32 i = 0; i < vsize(msg->stream->sub_topics); i++) {
        if (strcmp(sget(*(str_t **)vat(msg->stream->sub_topics, i)),
                   srrp_get_anchor(msg->pac)) == 0) {
            str_free(*(str_t **)vat(msg->stream->sub_topics, i));
            vremove(msg->stream->sub_topics, i, 1);
            break;
        }
    }

    struct srrp_packet *pub = srrp_new_publish(
        srrp_get_anchor(msg->pac), "{\"state\":\"unsub\"}");
    srrp_stream_send(msg->stream, pub);
    srrp_free(pub);

    message_finish(msg);
}

static void forward_request_or_response(struct message *msg)
{
    struct srrp_stream *dst = NULL;

    dst = srrpr_find_stream_by_l_nodeid(msg->stream->router, srrp_get_dstid(msg->pac));
    LOG_TRACE("[%p:forward_rr_l] dstid:%s, dst:%p",
              msg->stream->router, srrp_get_dstid(msg->pac), dst);
    if (dst) {
        msg->forward = dst;
        return;
    }

    dst = srrpr_find_stream_by_r_nodeid(msg->stream->router, srrp_get_dstid(msg->pac));
    LOG_TRACE("[%p:forward_rr_r] dstid:%s, dst:%p",
              msg->stream->router, srrp_get_dstid(msg->pac), dst);
    if (dst) {
        srrp_stream_send(dst, msg->pac);
        message_finish(msg);
        return;
    }

    srrp_stream_send_response(
        msg->stream, msg->pac, "{\"err\":404,\"msg\":\"Destination not found\"}");
    message_finish(msg);
    return;
}

static void forward_publish(struct message *msg)
{
    regex_t regex;
    int rc;

    struct srrp_stream *pos;
    list_for_each_entry(pos, &msg->stream->router->streams, ln) {
        for (u32 i = 0; i < vsize(pos->sub_topics); i++) {
            //LOG_TRACE("[%p:forward_publish] topic:%s, sub:%s",
            //          ctx, srrp_get_anchor(msg->pac), sget(*(str_t **)vat(pos->sub_topics, i)));
            rc = regcomp(&regex, sget(*(str_t **)vat(pos->sub_topics, i)), 0);
            if (rc != 0) continue;
            rc = regexec(&regex, srrp_get_anchor(msg->pac), 0, NULL, 0);
            if (rc == 0) {
                srrp_stream_send(pos, msg->pac);
            }
            regfree(&regex);
        }
    }

    message_finish(msg);
}

static void
handle_forward(struct message *msg)
{
    LOG_TRACE("[%p:handle_forward] state:%d, raw:%s",
              msg->stream->router, msg->state, srrp_get_raw(msg->pac));

    if (srrp_get_leader(msg->pac) == SRRP_REQUEST_LEADER ||
        srrp_get_leader(msg->pac) == SRRP_RESPONSE_LEADER) {
        forward_request_or_response(msg);
    } else if (srrp_get_leader(msg->pac) == SRRP_PUBLISH_LEADER) {
        forward_publish(msg);
    } else {
        assert(false);
    }
}

static void handle_message(struct srrp_router *router)
{
    struct message *pos;
    list_for_each_entry(pos, &router->msgs, ln) {
        if (pos->state == MESSAGE_ST_NONE || pos->state == MESSAGE_ST_FORWARD) {
            assert(srrp_get_ver(pos->pac) == SRRP_VERSION);
            LOG_TRACE("[%p:handle_message] #%d msg:%p, state:%d, raw:%s",
                    router, cio_stream_get_fd(pos->stream->stream),
                    pos, pos->state, srrp_get_raw(pos->pac));

            if (srrp_get_leader(pos->pac) == SRRP_CTRL_LEADER) {
                handle_ctrl(pos);
                continue;
            }

            if (pos->stream->r_nodeid == 0) {
                LOG_DEBUG("[%p:handle_message] #%d nodeid zero: "
                        "l_nodeid:%d, r_nodeid:%d, state:%d, raw:%s",
                        router, cio_stream_get_fd(pos->stream->stream),
                        pos->stream->l_nodeid, pos->stream->r_nodeid,
                        pos->state, srrp_get_raw(pos->pac));
                if (srrp_get_leader(pos->pac) == SRRP_REQUEST_LEADER)
                    srrp_stream_send_response(
                        pos->stream, pos->pac,
                        "{\"err\":1, \"msg\":\"nodeid not sync\"}");
                message_finish(pos);
                continue;
            }

            if (srrp_get_leader(pos->pac) == SRRP_SUBSCRIBE_LEADER) {
                handle_subscribe(pos);
                continue;
            }

            if (srrp_get_leader(pos->pac) == SRRP_UNSUBSCRIBE_LEADER) {
                handle_unsubscribe(pos);
                continue;
            }

            if (pos->state == MESSAGE_ST_FORWARD) {
                handle_forward(pos);
                continue;
            }

            // for SRRP_REQUEST_LEADER & SRRP_RESPONSE_LEADER
            pos->state = MESSAGE_ST_WAITING;
            //LOG_TRACE("[%p:handle_message] set srrp_packet_in", stream->ctx);
        }
    }
}

static void clear_finished_message(struct srrp_router *router)
{
    struct message *pos, *n;
    list_for_each_entry_safe(pos, n, &router->msgs, ln) {
        if (message_is_finished(pos))
            message_drop(pos);
    }
}

static void srrpr_sync(struct srrp_router *router)
{
    struct srrp_stream *ss;
    list_for_each_entry(ss, &router->streams, ln) {
        // sync
        if (ss->ts_sync_out + (STREAM_SYNC_TIMEOUT / 1000) < time(0)) {
            srrp_stream_sync_nodeid(ss);
        }

        // parse rxbuf to srrp_packet
        if (vsize(ss->rxbuf)) {
            srrp_stream_parse_packet(ss);
        }
    }
}

static void srrpr_poll(struct srrp_router *router, u64 usec)
{
    assert(cio_poll(router->ctx, usec) == 0);
    for (;;) {
        struct cio_event *ev = cio_iter(router->ctx);
        if (!ev) break;
        int token;
        switch ((token = cioe_get_token(ev))) {
            case TOKEN_LISTENER: {
                struct srrp_listener *sl = cioe_get_wrapper(ev);
                struct cio_stream *new_stream = cio_listener_accept(sl->listener);
                struct srrp_stream *ss = srrp_stream_new(
                    router, new_stream, 1, sget(sl->l_nodeid));
                list_add(&ss->ln, &router->streams);
                cio_register(router->ctx, cio_stream_get_fd(new_stream),
                             TOKEN_STREAM, CIOF_READABLE | CIOF_WRITABLE, ss);
                break;
            }
            case TOKEN_STREAM: {
                struct srrp_stream *ss = cioe_get_wrapper(ev);
                if (cioe_is_readable(ev)) {
                    char buf[1024] = {0};
                    int nr = cio_stream_recv(ss->stream, buf, sizeof(buf));
                    if (nr == 0 || nr == -1) {
                        struct message *pos, *n;
                        list_for_each_entry_safe(pos, n, &router->msgs, ln) {
                            if (pos->stream == ss) {
                                message_drop(pos);
                            }
                        }
                        cio_unregister(router->ctx, cio_stream_get_fd(ss->stream));
                        srrp_stream_drop(ss);
                    } else {
                        vpack(ss->rxbuf, buf, nr);
                        u8 fin = 0;
                        vpush(ss->rxbuf, &fin);
                        vpop(ss->rxbuf, &fin);
                        gettimeofday(&ss->ts_recv, NULL);
                    }
                }
                if (cioe_is_writable(ev)) {
                    if (vsize(ss->txbuf)) {
                        int nr = cio_stream_send(
                            ss->stream, vraw(ss->txbuf), vsize(ss->txbuf));
                        if (nr > 0) {
                            assert((u32)nr <= vsize(ss->txbuf));
                            LOG_TRACE("[%p:send] #%d msg:%s", ss->router,
                                      cio_stream_get_fd(ss->stream),
                                      vraw(ss->txbuf));
                            vdrop(ss->txbuf, nr);
                        }
                        if (vsize(ss->txbuf) == 0) {
                            cio_register(router->ctx, cio_stream_get_fd(ss->stream),
                                         token, CIOF_READABLE, ss);
                        }
                    }
                }
                break;
            }
        }
    }
}

static void srrpr_deal(struct srrp_router *router)
{
    if (!list_empty(&router->msgs)) {
        handle_message(router);
        clear_finished_message(router);
    }
}

int srrpr_wait(struct srrp_router *router, u64 usec)
{
    srrpr_sync(router);
    srrpr_poll(router, usec);
    srrpr_deal(router);

    if (list_empty(&router->msgs)) {
        return 0;
    } else {
        return 1;
    }
}

struct srrp_packet *srrpr_iter(struct srrp_router *router)
{
    struct message *msg;
    list_for_each_entry(msg, &router->msgs, ln) {
        if (msg->state == MESSAGE_ST_WAITING) {
            message_finish(msg);
            return msg->pac;
        }
    }

    return NULL;
}

int srrpr_send(struct srrp_router *router, struct srrp_packet *pac)
{
    int retval = -1;

    if (srrp_get_dstid(pac) != 0) {
        struct srrp_stream *local_stream =
            srrpr_find_stream_by_l_nodeid(router, srrp_get_dstid(pac));
        assert(local_stream == NULL);

        struct srrp_stream *remote_stream =
            srrpr_find_stream_by_r_nodeid(router, srrp_get_dstid(pac));
        if (remote_stream) {
            srrp_stream_send(remote_stream, pac);
            retval = 0;
        }
    }

    return retval;
}

int srrpr_forward(struct srrp_router *router, struct srrp_packet *pac)
{
    struct message *pos;
    list_for_each_entry(pos, &router->msgs, ln) {
        if (pos->pac == pac) {
            message_forward(pos);
            return 0;
        }
    }
    return -1;
}

/**
 * srrp_connect
 */

struct srrp_connect *
srrpc_new(struct cio_stream *stream, int owned, const char *nodeid)
{
    struct srrp_router *router = srrpr_new();
    srrpr_add_stream(router, stream, owned, nodeid);
    return (struct srrp_connect *)router;
}

void srrpc_drop(struct srrp_connect *conn)
{
    srrpr_drop((struct srrp_router *)conn);
}

int srrpc_wait(struct srrp_connect *conn, u64 usec)
{
    return srrpr_wait((struct srrp_router *)conn, usec);
}

int srrpc_wait_until(struct srrp_connect *conn)
{
    while (srrpc_wait(conn, WAIT_TIMEOUT) == 0);
    return 0;
}

struct srrp_packet *srrpc_iter(struct srrp_connect *conn)
{
    return srrpr_iter((struct srrp_router *)conn);
}

struct srrp_packet *srrpc_iter_pending(struct srrp_connect *conn)
{
    struct srrp_router *router = (struct srrp_router *)conn;
    struct message *msg;
    list_for_each_entry(msg, &router->msgs, ln) {
        if (msg->state == MESSAGE_ST_PENDING) {
            return msg->pac;
        }
    }

    return NULL;
}

int srrpc_send(struct srrp_connect *conn, struct srrp_packet *pac)
{
    struct srrp_router *router = (struct srrp_router *)conn;
    assert(!list_empty(&router->streams));
    assert(router->streams.next == router->streams.prev);
    struct srrp_stream *ss = container_of(router->streams.next, struct srrp_stream, ln);
    srrp_stream_send(ss, pac);
    return 0;
}

int srrpc_pending(struct srrp_connect *conn, struct srrp_packet *pac)
{
    struct srrp_router *router = (struct srrp_router *)conn;
    struct message *pos;
    list_for_each_entry(pos, &router->msgs, ln) {
        if (pos->pac == pac) {
            message_pending(pos);
            return 0;
        }
    }
    return -1;
}

int srrpc_finished(struct srrp_connect *conn, struct srrp_packet *pac)
{
    struct srrp_router *router = (struct srrp_router *)conn;
    struct message *pos;
    list_for_each_entry(pos, &router->msgs, ln) {
        if (pos->pac == pac) {
            message_finish(pos);
            return 0;
        }
    }
    return -1;
}
