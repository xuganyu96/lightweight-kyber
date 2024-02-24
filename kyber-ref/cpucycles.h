#ifndef CPUCYCLES_H
#define CPUCYCLES_H

#include <stdint.h>

// TODO: Figure out a way to streamline compiling for Apple Silicon
// #define USE_APPLE_SILICON

#ifdef USE_RDPMC  /* Needs echo 2 > /sys/devices/cpu/rdpmc */

static inline uint64_t cpucycles(void) {
  const uint32_t ecx = (1U << 30) + 1;
  uint64_t result;

  __asm__ volatile ("rdpmc; shlq $32,%%rdx; orq %%rdx,%%rax"
    : "=a" (result) : "c" (ecx) : "rdx");

  return result;
}

#elif defined USE_APPLE_SILICON

static inline uint64_t cpucycles(void) {
  uint64_t result;

  __asm__ volatile ("isb; mrs %0, CNTVCT_EL0" : "=r"(result));

  return result;
}

#else

static inline uint64_t cpucycles(void) {
  uint64_t result;

  __asm__ volatile ("rdtsc; shlq $32,%%rdx; orq %%rdx,%%rax"
    : "=a" (result) : : "%rdx");

  return result;
}

#endif

uint64_t cpucycles_overhead(void);

#endif
