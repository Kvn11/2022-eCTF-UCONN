#include "common.h"

void little_to_big32(uint32_t* data, size_t len)
{
    uint8_t* u8_datum = (uint8_t*)data;
    for(size_t i = 0; i < len; i++)
    {
        uint32_t u32_datum = data[i];
        u8_datum[(i*4)+0] = (uint8_t)(u32_datum >> 24);
        u8_datum[(i*4)+1] = (uint8_t)(u32_datum >> 16);
        u8_datum[(i*4)+2] = (uint8_t)(u32_datum >> 8);
        u8_datum[(i*4)+3] = (uint8_t)(u32_datum);
    }
}

void *memory_copy(void* dest, const void* src, size_t len){
    uint8_t* d = dest;
    const uint8_t* s = src;
    while(len--) *d++ = *s++; // move from one buffer to another
    return dest;
}

// implementation of memset (named memory_set to avoid automatic linkage)
void *memory_set(void* dest, int set, size_t len){
    uint8_t* d = dest;
    while(len--) *d++ = set; // same as memory_copy except we dont move from a source buffer
    return dest;
}