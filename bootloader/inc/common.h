#ifndef __UCONN_COMMON_H_
#define __UCONN_COMMON_H_

#include <stddef.h>
#include <stdint.h>

static inline void u32to8_little(uint8_t *p, const uint32_t *w)
{
    p[0] = (uint8_t)*w;
    p[1] = (uint8_t)(*w >> 8);
    p[2] = (uint8_t)(*w >> 16);
    p[3] = (uint8_t)(*w >> 24);
}

static inline void u8to32_little(uint32_t *w, const uint8_t *p)
{
    *w = (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24;
}

static inline void u32to8_big(uint8_t *p, const uint32_t *w)
{
    p[0] = (uint8_t)(*w >> 24);
    p[1] = (uint8_t)(*w >> 16);
    p[2] = (uint8_t)(*w >> 8);
    p[3] = (uint8_t)*w;
}

static inline void u8to32_big(uint32_t *w, const uint8_t *p)
{
    *w = (uint32_t)p[3] | (uint32_t)p[2]<<8 | (uint32_t)p[1]<<16 | (uint32_t)p[0]<<24;
}

static inline uint32_t load_u8to32_little(const uint8_t *p)
{
    uint32_t w;

    u8to32_little(&w, p);
    return w;
}

static inline uint32_t load_u8to32_big(const uint8_t *p)
{
    uint32_t w;

    u8to32_big(&w, p);
    return w;
}

#define LOAD_U32_LITTLE(p) load_u8to32_little(p)
#define LOAD_U32_BIG(p) load_u8to32_big(p)

#define STORE_U32_LITTLE(p, w) u32to8_little((p), &(w))
#define STORE_U32_BIG(p, w) u32to8_big((p), &(w))

// these need to be defined and implemented as QEMU cant find the linkable ASM files
void* memory_copy(void* dest, const void* src, size_t len);
void* memory_set(void* dest, int set, size_t len);

#endif