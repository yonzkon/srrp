#ifndef __SRRP_ROUTER_H
#define __SRRP_ROUTER_H

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct cio_listener;
struct cio_stream;

struct srrp_packet;
struct srrp_router;

struct srrp_router *srrpr_new();
void srrpr_drop(struct srrp_router *router);

void srrpr_add_listener(
    struct srrp_router *router, struct cio_listener *listener, const char *nodeid);
void srrpr_add_stream(
    struct srrp_router *router, struct cio_stream *stream, const char *nodeid);

struct cio_stream *srrpr_check_fin(struct srrp_router *router);
struct cio_stream *srrpr_check_accept(struct srrp_router *router);
int srrpr_wait(struct srrp_router *router, u64 usec);
struct srrp_packet *srrpr_iter(struct srrp_router *router);
int srrpr_send(struct srrp_router *router, struct srrp_packet *pac);
int srrpr_forward(struct srrp_router *router, struct srrp_packet *pac);

#ifdef __cplusplus
}
#endif
#endif
