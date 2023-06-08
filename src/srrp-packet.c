#include <assert.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "srrp-packet.h"
#include "crc16.h"
#include "str.h"
#include "vec.h"

#define CRC_SIZE 5 /* <crc16>\0 */

struct srrp_packet {
    char leader;
    u8 fin;
    u16 ver;
    u8 payload_type;

    u16 packet_len;
    u32 payload_len;

    str_t *srcid;
    str_t *dstid;

    str_t *anchor;
    const u8 *payload;

    u16 crc16;
    vec_t *raw;
};

char srrp_get_leader(const struct srrp_packet *pac)
{
    return pac->leader;
}

u8 srrp_get_fin(const struct srrp_packet *pac)
{
    return pac->fin;
}

u16 srrp_get_ver(const struct srrp_packet *pac)
{
    return pac->ver;
}

u8 srrp_get_payload_type(const struct srrp_packet *pac)
{
    return pac->payload_type;
}

u16 srrp_get_packet_len(const struct srrp_packet *pac)
{
    return pac->packet_len;
}

u32 srrp_get_payload_len(const struct srrp_packet *pac)
{
    return pac->payload_len;
}

const char *srrp_get_srcid(const struct srrp_packet *pac)
{
    return sget(pac->srcid);
}

const char *srrp_get_dstid(const struct srrp_packet *pac)
{
    return sget(pac->dstid);
}

const char *srrp_get_anchor(const struct srrp_packet *pac)
{
    return sget(pac->anchor);
}

const u8 *srrp_get_payload(const struct srrp_packet *pac)
{
    return pac->payload;
}

u16 srrp_get_crc16(const struct srrp_packet *pac)
{
    return pac->crc16;
}

const u8 *srrp_get_raw(const struct srrp_packet *pac)
{
    return vraw(pac->raw);
}

void srrp_set_fin(struct srrp_packet *pac, u8 fin)
{
    assert(fin == SRRP_FIN_0 || fin == SRRP_FIN_1);

    if (pac->fin == fin)
        return;

    pac->fin = fin;
    *((char *)vraw(pac->raw) + 1) = fin + '0';

    u16 crc = crc16(vraw(pac->raw), vsize(pac->raw) - CRC_SIZE);
    snprintf((char *)vraw(pac->raw) + vsize(pac->raw) - CRC_SIZE,
             CRC_SIZE, "%.4x", crc);
}

void srrp_set_payload_type(struct srrp_packet *pac, u8 payload_type)
{
    pac->payload_type = payload_type;
}

void srrp_free(struct srrp_packet *pac)
{
#ifdef DEBUG_SRRP
    printf("srrp_free: %p\n", pac);
#endif

    str_free(pac->srcid);
    str_free(pac->dstid);
    str_free(pac->anchor);
    vec_free(pac->raw);

    free(pac);
}

struct srrp_packet *srrp_move(struct srrp_packet *fst, struct srrp_packet *snd)
{
    // should not call srrp_free as it will free snd ...
    str_free(snd->anchor);
    vec_free(snd->raw);
    *snd = *fst;
    memset(fst, 0, sizeof(*fst));
    free(fst);
    return snd;
}

struct srrp_packet *srrp_cat(
    const struct srrp_packet *fst, const struct srrp_packet *snd)
{
    if (fst->leader != snd->leader)
        return NULL;
    if (fst->fin != SRRP_FIN_0)
        return NULL;
    if (fst->ver != snd->ver)
        return NULL;
    if (strcmp(sget(fst->srcid), sget(snd->srcid)) != 0)
        return NULL;
    if (strcmp(sget(fst->dstid), sget(snd->dstid)) != 0)
        return NULL;
    if (strcmp(sget(fst->anchor), sget(snd->anchor)) != 0)
        return NULL;
    //assert(snd->payload_len != 0);

    vec_t *v = vec_new(1, fst->payload_len + snd->payload_len);
    vpack(v, fst->payload, fst->payload_len);
    vpack(v, snd->payload, snd->payload_len);

    struct srrp_packet *retpac = srrp_new(
        fst->leader, snd->fin,
        sget(fst->srcid), sget(fst->dstid),
        sget(fst->anchor),
        vraw(v), vsize(v));

    vec_free(v);
    return retpac;
}

u32 srrp_next_packet_offset(const u8 *buf, u32 len)
{
    for (u32 i = 0; i < len; i++) {
        if (buf[i] == SRRP_CTRL_LEADER ||
            buf[i] == SRRP_REQUEST_LEADER ||
            buf[i] == SRRP_RESPONSE_LEADER ||
            buf[i] == SRRP_SUBSCRIBE_LEADER ||
            buf[i] == SRRP_UNSUBSCRIBE_LEADER ||
            buf[i] == SRRP_PUBLISH_LEADER) {
            if (i + 3 < len) {
                if (buf[i+2] - '0' == SRRP_VERSION_MAJOR &&
                    buf[i+3] - '0' == SRRP_VERSION_MINOR) {
                    return i;
                }
            } else {
                return i;
            }
        }
    }
    return len;
}

struct srrp_packet *srrp_parse(const u8 *buf, u32 len)
{
    char leader = 0;
    u8 fin = 0;
    u16 ver = 0;
    u8 payload_type = 0;
    u16 packet_len = 0;
    u32 payload_len = 0;
    char srcid[SRRP_ID_MAX] = {0};
    char dstid[SRRP_ID_MAX] = {0};
    char anchor[SRRP_ANCHOR_MAX] = {0};

    leader = buf[0];

    if (leader == SRRP_CTRL_LEADER ||
        leader == SRRP_REQUEST_LEADER ||
        leader == SRRP_RESPONSE_LEADER) {
        // 1024 means SRRP_ANCHOR_MAX
        if (sscanf((char *)buf + 1, "%c%hx%c#%hx#%x#%255[^#]#%255[^:]:%1023[^?]",
                   &fin, &ver, &payload_type, &packet_len, &payload_len,
                   srcid, dstid, anchor) != 8)
            return NULL;
        if (strlen(srcid) == 0 || strlen(dstid) == 0)
            return NULL;
    } else if (leader == SRRP_SUBSCRIBE_LEADER ||
               leader == SRRP_UNSUBSCRIBE_LEADER ||
               leader == SRRP_PUBLISH_LEADER) {
        // 1024 means SRRP_ANCHOR_MAX
        if (sscanf((char *)buf + 1, "%c%hx%c#%hx#%x:%1023[^?]",
                   &fin, &ver, &payload_type, &packet_len, &payload_len, anchor) != 6)
            return NULL;
    } else {
        return NULL;
    }

    if (packet_len > len)
        return NULL;

    u16 crc = 0;

    if (sscanf((char *)buf + packet_len - CRC_SIZE, "%4hx", &crc) != 1)
        return NULL;

    if (crc != crc16(buf, packet_len - CRC_SIZE))
        return NULL;

    struct srrp_packet *pac = calloc(1, sizeof(*pac));
    assert(pac);

    pac->raw = vec_new(1, packet_len);
    assert(pac->raw);
    vpack(pac->raw, buf, packet_len);

    pac->leader = leader;
    pac->fin = fin - '0';
    pac->ver = ver;
    pac->payload_type = payload_type;
    pac->packet_len = packet_len;
    pac->payload_len = payload_len;

    pac->srcid = str_new(srcid);
    pac->dstid = str_new(dstid);

    pac->anchor = str_new(anchor);
    assert(pac->anchor);
    if (pac->payload_len == 0) {
        pac->payload = vraw(pac->raw) + strlen(vraw(pac->raw));
    } else {
        pac->payload = (u8 *)strstr(vraw(pac->raw), "?");
        if (pac->payload) pac->payload += 1;
    }

    pac->crc16 = crc;
#ifdef DEBUG_SRRP
    printf("srrp_new : %p\n", pac);
#endif
    return pac;
}

static vec_t *__srrp_new_raw(
    char leader, u8 fin, const char *srcid, const char *dstid,
    const char *anchor, const u8 *payload, u32 payload_len)
{
    char tmp[32] = {0};

    vec_t *v = vec_new(1, 0);
    assert(v);

    // leader
    vpush(v, &leader);

    // fin
    u8 tmp_fin = fin + '0';
    vpush(v, &tmp_fin);

    // ver2
    snprintf(tmp, sizeof(tmp), "%.1x%.1x", SRRP_VERSION_MAJOR, SRRP_VERSION_MINOR);
    assert(strlen(tmp) == 2);
    vpack(v, tmp, 2);

    // payload_type, default json
    vpack(v, "j", 1);

//#define VINSERT
#ifndef VINSERT
    // packet_len
    vpack(v, "#____", 5);
#else
    vpack(v, "#", 1);
#endif

    // payload_len
    snprintf(tmp, sizeof(tmp), "#%x", payload_len);
    vpack(v, tmp, strlen(tmp));

    if (leader == SRRP_CTRL_LEADER ||
        leader == SRRP_REQUEST_LEADER ||
        leader == SRRP_RESPONSE_LEADER) {
        // srcid
        assert(srcid);
        vpack(v, "#", 1);
        vpack(v, srcid, strlen(srcid));
        // dstid
        vpack(v, "#", 1);
        if (leader == SRRP_CTRL_LEADER) {
            vpack(v, "0", 1);
        } else {
            assert(dstid);
            vpack(v, dstid, strlen(dstid));
        }
    }

    // anchor
    vpack(v, ":", 1);
    vpack(v, anchor, strlen(anchor));

    // payload
    if (payload_len) {
        vpack(v, "?", 1);
        vpack(v, payload, payload_len);
    }

    // stop flag
    vpack(v, "\0", 1);

    // packet_len
#ifndef VINSERT
    u16 packet_len = vsize(v) + CRC_SIZE;
    assert(packet_len < SRRP_PACKET_MAX);
    snprintf(tmp, sizeof(tmp), "%.4x", packet_len);
    assert(strlen(tmp) == 4);
    memcpy((char *)vraw(v) + 6, tmp, 4);
#else
    u16 packet_len = vsize(v) + CRC_SIZE + 4;
    assert(packet_len < SRRP_PACKET_MAX);
    snprintf(tmp, sizeof(tmp), "%.4x", packet_len);
    assert(strlen(tmp) == 4);
    vinsert(v, 6, tmp, 4);
#endif

    // crc16
    u16 crc = crc16(vraw(v), vsize(v));
    snprintf(tmp, sizeof(tmp), "%.4x", crc);
    assert(strlen(tmp) == 4);
    vpack(v, tmp, strlen(tmp));
    vpack(v, "\0", 1);

    vshrink(v);
    return v;
}

struct srrp_packet *srrp_new(
    char leader, u8 fin, const char *srcid, const char *dstid,
    const char *anchor, const u8 *payload, u32 payload_len)
{
    vec_t *v = __srrp_new_raw(
        leader, fin, srcid, dstid, anchor, payload, payload_len);

    struct srrp_packet *pac = calloc(1, sizeof(*pac));
    assert(pac);
    pac->raw = v;

    pac->leader = leader;
    pac->fin = fin;
    pac->ver = SRRP_VERSION;
    pac->payload_type = SRRP_PAYLOAD_JSON;
    pac->packet_len = vsize(v);
    pac->payload_len = payload_len;

    if (srcid) {
        pac->srcid = str_new(srcid);
    } else {
        pac->srcid = str_new("");
    }
    if (dstid) {
        pac->dstid = str_new(dstid);
    } else {
        pac->dstid = str_new("");
    }

    pac->anchor = str_new(anchor);
    assert(pac->anchor);
    if (pac->payload_len == 0) {
        pac->payload = vraw(pac->raw) + strlen(vraw(pac->raw));
    } else {
        pac->payload = (u8 *)strstr(vraw(pac->raw), "?");
        if (pac->payload) pac->payload += 1;
    }

    sscanf(vraw(v) + vsize(v) - CRC_SIZE, "%4hx", &pac->crc16);

#ifdef DEBUG_SRRP
    printf("srrp_new : %p\n", pac);
#endif
    return pac;
}
