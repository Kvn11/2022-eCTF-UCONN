#include "common.h"

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