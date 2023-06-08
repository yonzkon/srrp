#ifndef __SRRP_CONNECT_H
#define __SRRP_CONNECT_H

#include "srrp.h"
#include "srrp-types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct cio_stream;
struct srrp_connect;

struct srrp_connect *srrpc_new(struct cio_stream *stream, const char *nodeid);
void srrpc_drop(struct srrp_connect *conn);

struct cio_stream *srrpc_check_fin(struct srrp_connect *conn);
int srrpc_wait(struct srrp_connect *conn, u64 usec);
int srrpc_wait_until(struct srrp_connect *conn);
struct srrp_packet *srrpc_wait_response(
    struct srrp_connect *conn, const char *srcid, const char *anchor);
struct srrp_packet *srrpc_iter(struct srrp_connect *conn);
struct srrp_packet *srrpc_iter_pending(struct srrp_connect *conn);
int srrpc_send(struct srrp_connect *conn, struct srrp_packet *pac);
int srrpc_pending(struct srrp_connect *conn, struct srrp_packet *pac);
int srrpc_finished(struct srrp_connect *conn, struct srrp_packet *pac);

#ifdef __cplusplus
}
#endif
#endif
