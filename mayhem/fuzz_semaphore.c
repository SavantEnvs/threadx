/* Counting semaphore and mutex driven side by side from an operation stream, with the
 * semaphore checked against a reference counter after every call. */
#include "fuzz_common.h"

static TX_SEMAPHORE sem;
static TX_MUTEX mtx;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    reader_t r = {data, size, 0};
    ULONG count = rd32(&r);
    UINT inherit = rd8(&r) & 1;

    if (tx_semaphore_create(&sem, "fuzz", count) != TX_SUCCESS)
        return -1;
    if (tx_mutex_create(&mtx, "fuzz", inherit) != TX_SUCCESS) {
        KDELETE(_tx_semaphore_delete(&sem));
        return -1;
    }

    ULONG model = count;
    ULONG owned = 0;

    for (int ops = 0; ops < MAX_OPS && !r.eof; ops++) {
        uint8_t op = rd8(&r) & 15;
        switch (op) {
        case 0:
        case 1:
            if (tx_semaphore_put(&sem) != TX_SUCCESS)
                abort();
            model++;
            break;
        case 2:
        case 3:
        case 4: {
            UINT st = tx_semaphore_get(&sem, TX_NO_WAIT);
            if (model == 0) {
                if (st != TX_NO_INSTANCE)
                    abort();
            } else {
                if (st != TX_SUCCESS)
                    abort();
                model--;
            }
            break;
        }
        case 5:
        case 6: {
            ULONG ceiling = rd32(&r);
            UINT st = tx_semaphore_ceiling_put(&sem, ceiling);
            if (ceiling == 0)
                break; /* rejected as an invalid ceiling */
            if (model >= ceiling) {
                if (st != TX_CEILING_EXCEEDED)
                    abort();
            } else {
                if (st != TX_SUCCESS)
                    abort();
                model++;
            }
            break;
        }
        case 7: {
            CHAR *name;
            ULONG cur;
            TX_THREAD *susp;
            UINT n;
            TX_SEMAPHORE *next;
            if (tx_semaphore_info_get(&sem, &name, &cur, &susp, &n, &next) != TX_SUCCESS)
                abort();
            if (cur != model)
                abort();
            break;
        }
        case 8:
            tx_semaphore_prioritize(&sem);
            break;
        case 9:
        case 10:
            if (tx_mutex_get(&mtx, TX_NO_WAIT) == TX_SUCCESS)
                owned++;
            break;
        case 11:
        case 12:
            if (tx_mutex_put(&mtx) == TX_SUCCESS) {
                if (owned == 0)
                    abort();
                owned--;
            }
            break;
        case 13: {
            CHAR *name;
            ULONG cnt, susp_cnt;
            TX_THREAD *owner, *susp;
            TX_MUTEX *next;
            if (tx_mutex_info_get(&mtx, &name, &cnt, &owner, &susp, &susp_cnt, &next) != TX_SUCCESS)
                abort();
            if (cnt != owned)
                abort();
            break;
        }
        case 14:
            tx_mutex_prioritize(&mtx);
            break;
        default:
            break;
        }
    }

    /* the initialization context is not a thread: leave the mutex as the kernel expects */
    while (owned > 0 && tx_mutex_put(&mtx) == TX_SUCCESS)
        owned--;
    KDELETE(_tx_mutex_delete(&mtx));
    KDELETE(_tx_semaphore_delete(&sem));
    return 0;
}
