/* Block pool: create over a heap buffer of the exact pool size, then allocate / release /
 * info / prioritize. Live blocks carry a per-slot pattern verified at release. */
#include "fuzz_common.h"

#define SLOTS 32

static TX_BLOCK_POOL pool;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    reader_t r = {data, size, 0};
    uint8_t *slot_ptr[SLOTS] = {0};

    ULONG block_size = rd8(&r);
    ULONG pool_size = rd16(&r);
    uint8_t *mem = malloc(pool_size ? pool_size : 1);
    if (mem == NULL)
        return -1;

    if (tx_block_pool_create(&pool, "fuzz", block_size, mem, pool_size) != TX_SUCCESS) {
        free(mem);
        return -1;
    }

    for (int ops = 0; ops < MAX_OPS && !r.eof; ops++) {
        uint8_t op = rd8(&r);
        unsigned s = (op >> 3) % SLOTS;
        switch (op & 7) {
        case 0:
        case 1:
        case 2: /* allocate */
            if (slot_ptr[s] == NULL) {
                VOID *p = NULL;
                if (tx_block_allocate(&pool, &p, TX_NO_WAIT) == TX_SUCCESS) {
                    slot_ptr[s] = p;
                    memset(p, s + 1, block_size);
                }
            }
            break;
        case 3:
        case 4:
        case 5: /* release */
            if (slot_ptr[s] != NULL) {
                for (ULONG i = 0; i < block_size; i++)
                    if (slot_ptr[s][i] != (uint8_t)(s + 1))
                        abort();
                if (tx_block_release(slot_ptr[s]) != TX_SUCCESS)
                    abort();
                slot_ptr[s] = NULL;
            }
            break;
        case 6: {
            CHAR *name;
            ULONG avail, total;
            TX_THREAD *susp;
            UINT n;
            TX_BLOCK_POOL *next;
            tx_block_pool_info_get(&pool, &name, &avail, &total, &susp, &n, &next);
            if (avail > total)
                abort();
            break;
        }
        default:
            tx_block_pool_prioritize(&pool);
            break;
        }
    }

    for (unsigned s = 0; s < SLOTS; s++)
        if (slot_ptr[s] != NULL) {
            for (ULONG i = 0; i < block_size; i++)
                if (slot_ptr[s][i] != (uint8_t)(s + 1))
                    abort();
            if (tx_block_release(slot_ptr[s]) != TX_SUCCESS)
                abort();
        }
    KDELETE(_tx_block_pool_delete(&pool));
    free(mem);
    return 0;
}
