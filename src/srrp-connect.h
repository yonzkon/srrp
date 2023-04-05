#ifndef __SRRP_CONNECT_H
#define __SRRP_CONNECT_H

#include <cio-stream.h>
#include "srrp-types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct srrp_connect;

struct srrp_connect *srrpc_new(struct cio_stream *stream, int owned, u32 nodeid);
void srrpc_drop(struct srrp_connect *conn);

int srrpc_wait(struct srrp_connect *conn, u64 usec);
struct srrp_packet *srrpc_iter(struct srrp_connect *conn);
int srrpc_send(struct srrp_connect *conn, struct srrp_packet *pac);

#ifdef __cplusplus
}
#endif
#endif
