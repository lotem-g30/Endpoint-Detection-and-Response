#include "event_queue.h"
#include <string.h>
#include <stdio.h>

void eq_init(EventQueue* q) {
    memset(q, 0, sizeof(*q));
    InitializeCriticalSection(&q->lock);
}

bool eq_push(EventQueue* q, const char* event) {
    if (strlen(event) >= EQ_MAX_EVENT_LEN) return false;

    EnterCriticalSection(&q->lock);

    int next_head = (q->head + 1) % EQ_CAPACITY;
    if (next_head == q->tail) {
        // Full - drop oldest
        q->tail = (q->tail + 1) % EQ_CAPACITY;
        q->dropped_count++;
    }

    strncpy(q->slots[q->head], event, EQ_MAX_EVENT_LEN - 1);
    q->slots[q->head][EQ_MAX_EVENT_LEN - 1] = '\0';
    q->head = next_head;

    LeaveCriticalSection(&q->lock);
    return true;
}

bool eq_pop(EventQueue* q, char* out, size_t out_size) {
    EnterCriticalSection(&q->lock);

    if (q->head == q->tail) {
        LeaveCriticalSection(&q->lock);
        return false;
    }

    strncpy(out, q->slots[q->tail], out_size - 1);
    out[out_size - 1] = '\0';
    q->tail = (q->tail + 1) % EQ_CAPACITY;

    LeaveCriticalSection(&q->lock);
    return true;
}

uint32_t eq_count(EventQueue* q) {
    EnterCriticalSection(&q->lock);
    uint32_t count = (q->head - q->tail + EQ_CAPACITY) % EQ_CAPACITY;
    LeaveCriticalSection(&q->lock);
    return count;
}

uint64_t eq_dropped(EventQueue* q) {
    return q->dropped_count;
}

void eq_destroy(EventQueue* q) {
    DeleteCriticalSection(&q->lock);
}
