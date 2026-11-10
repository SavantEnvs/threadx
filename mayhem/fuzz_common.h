/* Shared scaffolding for the ThreadX service fuzzers (Linux port, kernel only).
 *
 * The kernel is brought up the way tx_kernel_enter() does, minus the scheduler: every service
 * is then called from the initialization context with TX_NO_WAIT, which is a documented calling
 * context for all of them. Each input creates its objects, drives them with a byte-coded
 * operation stream and deletes them again, so no state survives from one input to the next.
 */
#ifndef MAYHEM_FUZZ_COMMON_H
#define MAYHEM_FUZZ_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "tx_api.h"
#include "tx_initialize.h"

extern volatile ULONG _tx_thread_system_state;

static void fuzz_kernel_up(void)
{
    static int up;
    if (up)
        return;
    up = 1;
    _tx_thread_system_state = TX_INITIALIZE_IN_PROGRESS;
    _tx_initialize_low_level();
    _tx_initialize_high_level();
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    fuzz_kernel_up();
    return 0;
}

/* Sequential reader over the fuzz input; reads past the end yield 0 and set `eof`. */
typedef struct {
    const uint8_t *p;
    size_t n;
    int eof;
} reader_t;

static inline uint8_t rd8(reader_t *r)
{
    if (r->n == 0) {
        r->eof = 1;
        return 0;
    }
    r->n--;
    return *r->p++;
}

static inline uint16_t rd16(reader_t *r)
{
    uint16_t lo = rd8(r);
    return (uint16_t)(lo | ((uint16_t)rd8(r) << 8));
}

static inline uint32_t rd32(reader_t *r)
{
    uint32_t lo = rd16(r);
    return lo | ((uint32_t)rd16(r) << 16);
}

/* The tx_*_delete wrappers refuse to run from the initialization context (TX_CALLER_ERROR), so
 * objects are removed with the kernel's own _tx_*_delete; a failed delete is a harness bug. */
#define KDELETE(call) do { if ((call) != TX_SUCCESS) abort(); } while (0)

#define MAX_OPS 512

#endif
