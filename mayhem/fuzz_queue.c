/* Queue: create with a fuzzed message size and storage size, then send / front-send / receive /
 * flush / info against a reference FIFO model (order, content, full/empty status). */
#include "fuzz_common.h"

#define MAXW 32
#define MODEL_CAP 20000

static TX_QUEUE queue;
static ULONG sends_notified;

static void notify(TX_QUEUE *q)
{
    (void)q;
    sends_notified++;
}

static uint32_t model_ids[MODEL_CAP];

static void make_msg(ULONG *m, UINT words, uint32_t id)
{
    for (UINT i = 0; i < words; i++)
        m[i] = id * 2654435761u + i;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    reader_t r = {data, size, 0};
    UINT words = rd8(&r);
    ULONG qbytes = rd16(&r);
    uint8_t *mem = malloc(qbytes ? qbytes : 1);
    if (mem == NULL)
        return -1;

    if (tx_queue_create(&queue, "fuzz", words, mem, qbytes) != TX_SUCCESS) {
        free(mem);
        return -1;
    }

    ULONG capacity = qbytes / (words * sizeof(ULONG));
    if (capacity > MODEL_CAP)
        abort();
    size_t head = 0, count = 0; /* model: model_ids[(head + i) % MODEL_CAP], i < count */
    uint32_t next_id = 1;
    ULONG expect_notified = 0;
    int notify_on = 0;
    sends_notified = 0;

    for (int ops = 0; ops < MAX_OPS && !r.eof; ops++) {
        ULONG msg[MAXW], got[MAXW];
        uint8_t op = rd8(&r) & 7;
        switch (op) {
        case 0:
        case 1: { /* send */
            uint32_t id = next_id++;
            make_msg(msg, words, id);
            UINT st = tx_queue_send(&queue, msg, TX_NO_WAIT);
            if (count == capacity) {
                if (st != TX_QUEUE_FULL)
                    abort();
            } else {
                if (st != TX_SUCCESS)
                    abort();
                model_ids[(head + count++) % MODEL_CAP] = id;
                expect_notified += notify_on;
            }
            break;
        }
        case 2: { /* front send */
            uint32_t id = next_id++;
            make_msg(msg, words, id);
            UINT st = tx_queue_front_send(&queue, msg, TX_NO_WAIT);
            if (count == capacity) {
                if (st != TX_QUEUE_FULL)
                    abort();
            } else {
                if (st != TX_SUCCESS)
                    abort();
                head = (head + MODEL_CAP - 1) % MODEL_CAP;
                model_ids[head] = id;
                count++;
                expect_notified += notify_on;
            }
            break;
        }
        case 3:
        case 4: { /* receive */
            memset(got, 0xEE, sizeof(got));
            UINT st = tx_queue_receive(&queue, got, TX_NO_WAIT);
            if (count == 0) {
                if (st != TX_QUEUE_EMPTY)
                    abort();
            } else {
                if (st != TX_SUCCESS)
                    abort();
                make_msg(msg, words, model_ids[head]);
                if (memcmp(msg, got, words * sizeof(ULONG)) != 0)
                    abort();
                head = (head + 1) % MODEL_CAP;
                count--;
            }
            break;
        }
        case 5:
            if (tx_queue_flush(&queue) != TX_SUCCESS)
                abort();
            count = 0;
            break;
        case 6: {
            CHAR *name;
            ULONG enq, avail;
            TX_THREAD *susp;
            UINT n;
            TX_QUEUE *next;
            if (tx_queue_info_get(&queue, &name, &enq, &avail, &susp, &n, &next) != TX_SUCCESS)
                abort();
            if (enq != count || enq + avail != capacity)
                abort();
            break;
        }
        default:
            notify_on = 1;
            tx_queue_send_notify(&queue, notify);
            break;
        }
    }

    if (sends_notified != expect_notified)
        abort();
    KDELETE(_tx_queue_delete(&queue));
    free(mem);
    return 0;
}
