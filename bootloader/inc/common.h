#ifndef __UCONN_COMMON_H_
#define __UCONN_COMMON_H_

#include <stddef.h>
#include <stdint.h>

// these need to be defined and implemented as QEMU cant find the linkable ASM files
void* memory_copy(void* dest, const void* src, size_t len);
void* memory_set(void* dest, int set, size_t len);

#endif