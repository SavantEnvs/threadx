/* Event flags group: set (OR/AND) and non-blocking get (OR/AND, with and without clear),
 * checked against a 32-bit reference value after every call. */
#include "fuzz_common.h"

static TX_EVENT_FLAGS_GROUP group;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    reader_t r = {data, size, 0};

    if (tx_event_flags_create(&group, "fuzz") != TX_SUCCESS)
        return -1;

    ULONG model = 0;

    for (int ops = 0; ops < MAX_OPS && !r.eof; ops++) {
        uint8_t op = rd8(&r) & 7;
        switch (op) {
        case 0:
        case 1: {
            ULONG v = rd32(&r);
            UINT opt = (op & 1) ? TX_OR : TX_AND;
            if (tx_event_flags_set(&group, v, opt) != TX_SUCCESS)
                abort();
            model = (op & 1) ? (model | v) : (model & v);
            break;
        }
        case 2:
        case 3:
        case 4:
        case 5: {
            ULONG req = rd32(&r);
            UINT opt = rd8(&r) & 3; /* TX_OR, TX_OR_CLEAR, TX_AND, TX_AND_CLEAR */
            ULONG actual = 0xDEADBEEF;
            UINT st = tx_event_flags_get(&group, req, opt, &actual, TX_NO_WAIT);
            int is_and = (opt & TX_AND) != 0;
            int clear = (opt & 1) != 0;
            /* a request for no flags is never satisfied, in either mode */
            int ok = req != 0 && (is_and ? ((model & req) == req) : ((model & req) != 0));
            if (ok) {
                if (st != TX_SUCCESS || actual != model)
                    abort();
                if (clear)
                    model &= ~req;
            } else if (st != TX_NO_EVENTS) {
                abort();
            }
            break;
        }
        case 6: {
            CHAR *name;
            ULONG cur;
            TX_THREAD *susp;
            UINT n;
            TX_EVENT_FLAGS_GROUP *next;
            if (tx_event_flags_info_get(&group, &name, &cur, &susp, &n, &next) != TX_SUCCESS)
                abort();
            if (cur != model)
                abort();
            break;
        }
        default:
            break;
        }
    }

    KDELETE(_tx_event_flags_delete(&group));
    return 0;
}
