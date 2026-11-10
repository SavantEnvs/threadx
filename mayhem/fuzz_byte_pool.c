/* Byte pool: create over a heap buffer of the exact pool size, then a stream of
 * allocate / release / info / prioritize calls. Every live allocation is filled with a
 * per-slot pattern and checked at release, so overlapping or corrupted blocks abort. */
#include "fuzz_common.h"

#define SLOTS 32

static TX_BYTE_POOL pool;

static void fill(uint8_t *p, ULONG n, uint8_t v) { memset(p, v, n); }

static void check(const uint8_t *p, ULONG n, uint8_t v)
{
    for (ULONG i = 0; i < n; i++)
        if (p[i] != v)
            abort();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    reader_t r = {data, size, 0};
    uint8_t *slot_ptr[SLOTS] = {0};
    ULONG slot_len[SLOTS] = {0};

    ULONG pool_size = rd16(&r);
    uint8_t *mem = malloc(pool_size ? pool_size : 1);
    if (mem == NULL)
        return -1;

    if (tx_byte_pool_create(&pool, "fuzz", mem, pool_size) != TX_SUCCESS) {
        free(mem);
        return -1;
    }

    for (int ops = 0; ops < MAX_OPS && !r.eof; ops++) {
        uint8_t op = rd8(&r);
        unsigned s = (op >> 3) % SLOTS;
        switch (op & 7) {
        case 0:
        case 1:
        case 2: { /* allocate: small / medium / any 32-bit size */
            ULONG n = (op & 7) == 0 ? rd8(&r) : (op & 7) == 1 ? rd16(&r) : rd32(&r);
            if (slot_ptr[s] != NULL)
                break;
            VOID *p = NULL;
            if (tx_byte_allocate(&pool, &p, n, TX_NO_WAIT) == TX_SUCCESS) {
                slot_ptr[s] = p;
                slot_len[s] = n;
                fill(p, n, (uint8_t)(s + 1));
            }
            break;
        }
        case 3:
        case 4: /* release */
            if (slot_ptr[s] != NULL) {
                check(slot_ptr[s], slot_len[s], (uint8_t)(s + 1));
                if (tx_byte_release(slot_ptr[s]) != TX_SUCCESS)
                    abort();
                slot_ptr[s] = NULL;
            }
            break;
        case 5: {
            CHAR *name;
            ULONG avail, frags;
            TX_THREAD *susp;
            UINT n;
            TX_BYTE_POOL *next;
            tx_byte_pool_info_get(&pool, &name, &avail, &frags, &susp, &n, &next);
            if (avail > pool_size)
                abort();
            break;
        }
        case 6:
            tx_byte_pool_prioritize(&pool);
            break;
        default: /* allocate-and-release at once, exercises the search + merge path */ {
            VOID *p = NULL;
            ULONG n = rd16(&r);
            if (tx_byte_allocate(&pool, &p, n, TX_NO_WAIT) == TX_SUCCESS) {
                fill(p, n, 0xA5);
                check(p, n, 0xA5);
                tx_byte_release(p);
            }
            break;
        }
        }
    }

    for (unsigned s = 0; s < SLOTS; s++)
        if (slot_ptr[s] != NULL) {
            check(slot_ptr[s], slot_len[s], (uint8_t)(s + 1));
            if (tx_byte_release(slot_ptr[s]) != TX_SUCCESS)
                abort();
        }
    KDELETE(_tx_byte_pool_delete(&pool));
    free(mem);
    return 0;
}
