#ifndef __SRRP_ROUTER_H
#define __SRRP_ROUTER_H

#include <cio-stream.h>
#include "srrp.h"
#include "srrp-types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct srrp_router;

struct srrp_router *srrpr_new();
void srrpr_drop(struct srrp_router *router);

void srrpr_add_listener(
    struct srrp_router *router, struct cio_listener *listener,
    int owned, const char *nodeid);
void srrpr_add_stream(
    struct srrp_router *router, struct cio_stream *stream,
    int owned, const char *nodeid);

int srrpr_wait(struct srrp_router *router, u64 usec);
struct srrp_packet *srrpr_iter(struct srrp_router *router);
int srrpr_send(struct srrp_router *router, struct srrp_packet *pac);
int srrpr_forward(struct srrp_router *router, struct srrp_packet *pac);

#ifdef __cplusplus
}
#endif
#endif
