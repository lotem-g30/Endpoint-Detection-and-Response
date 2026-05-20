#pragma once
#include <windows.h>
#include <stdint.h>
#include <stdbool.h>

#define EQ_CAPACITY      4096
#define EQ_MAX_EVENT_LEN 2048

typedef struct {
    char     slots[EQ_CAPACITY][EQ_MAX_EVENT_LEN];
    uint32_t head;
    uint32_t tail;
    uint32_t count;
    uint64_t dropped_count;
    CRITICAL_SECTION lock;
} EventQueue;

void     eq_init(EventQueue* q);
void     eq_destroy(EventQueue* q);
bool     eq_push(EventQueue* q, const char* event_json);
bool     eq_pop(EventQueue* q, char* buf, size_t buf_len);
uint32_t eq_count(EventQueue* q);
uint64_t eq_dropped(EventQueue* q);