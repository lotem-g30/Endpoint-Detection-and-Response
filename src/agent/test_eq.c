/*
 * test_eq_standalone.c
 * Unit tests for EventQueue � no pipe, no DLL, no external dependencies.
 *
 * Build:
 *   cl /std:c17 exercises\test_eq_standalone.c src\hook_dll\event_queue.c ^
 *      /Fe:test_eq.exe /I include
 *
 * Expected output:
 *   [pop] event_0
 *   [pop] event_1
 *   [pop] event_2
 *   [pop] event_3
 *   [pop] event_4
 *   [empty pop] returned false: OK
 *   [overflow] eq_dropped() = 1
 *   [overflow] oldest surviving item: overflow_1
 *   All checks passed.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../src/hook_dll/event_queue.h"

 /* Simple assert helper � prints the failed check and exits */
#define CHECK(cond, msg)                                        \
    do {                                                        \
        if (!(cond)) {                                          \
            fprintf(stderr, "[FAIL] %s (line %d)\n",           \
                    msg, __LINE__);                             \
            exit(1);                                            \
        }                                                       \
    } while (0)

/* ------------------------------------------------------------------ */
/* Test 1: basic push / pop in order                                   */
/* ------------------------------------------------------------------ */
static void test_push_pop_order(void)
{
    static EventQueue q;
    eq_init(&q);

    /* Push 5 events */
    for (int i = 0; i < 5; i++) {
        char event[64];
        snprintf(event, sizeof(event), "event_%d", i);
        bool ok = eq_push(&q, event);
        CHECK(ok, "eq_push should return true when queue has space");
    }

    CHECK(eq_count(&q) == 5, "count should be 5 after 5 pushes");

    /* Pop and verify order */
    for (int i = 0; i < 5; i++) {
        char buf[EQ_MAX_EVENT_LEN];
        bool ok = eq_pop(&q, buf, sizeof(buf));
        CHECK(ok, "eq_pop should return true when queue is non-empty");

        char expected[64];
        snprintf(expected, sizeof(expected), "event_%d", i);
        CHECK(strcmp(buf, expected) == 0, "popped event should match pushed event");

        printf("[pop] %s\n", buf);
    }

    CHECK(eq_count(&q) == 0, "count should be 0 after all pops");

    eq_destroy(&q);
}

/* ------------------------------------------------------------------ */
/* Test 2: pop on empty queue returns false                             */
/* ------------------------------------------------------------------ */
static void test_empty_pop(void)
{
    static EventQueue q;
    eq_init(&q);

    char buf[EQ_MAX_EVENT_LEN];
    bool ok = eq_pop(&q, buf, sizeof(buf));
    CHECK(!ok, "eq_pop on empty queue should return false");
    printf("[empty pop] returned false: OK\n");

    eq_destroy(&q);
}

/* ------------------------------------------------------------------ */
/* Test 3: overflow drops the OLDEST entry, dropped counter increments */
/* ------------------------------------------------------------------ */
static void test_overflow(void)
{
    static EventQueue q;
    eq_init(&q);

    /*
     * Fill the queue to capacity (EQ_CAPACITY - 1 usable slots because
     * head == tail means empty; one slot is always reserved as the gap).
     * Then push one more to force a drop.
     *
     * We use a small logical capacity here: push EQ_CAPACITY events.
     * The first push that would make head == tail triggers the drop,
     * which advances tail (discards the oldest entry).
     */

     /* Push exactly EQ_CAPACITY events � the last one triggers an overflow */
    for (int i = 0; i < EQ_CAPACITY; i++) {
        char event[64];
        snprintf(event, sizeof(event), "overflow_%d", i);
        eq_push(&q, event);   /* may or may not drop; we'll verify below */
    }

    /* After filling, eq_dropped() must be >= 1 */
    uint64_t dropped = eq_dropped(&q);
    CHECK(dropped >= 1, "eq_dropped() should be >= 1 after overflow");
    printf("[overflow] eq_dropped() = %llu\n", (unsigned long long)dropped);

    /*
     * The oldest surviving item should be "overflow_1"
     * (overflow_0 was the one evicted to make room for overflow_EQ_CAPACITY-1).
     */
    char buf[EQ_MAX_EVENT_LEN];
    bool ok = eq_pop(&q, buf, sizeof(buf));
    CHECK(ok, "queue should be non-empty after overflow");
    CHECK(strcmp(buf, "overflow_1") == 0,
        "oldest surviving item after overflow should be overflow_1");
    printf("[overflow] oldest surviving item: %s\n", buf);

    eq_destroy(&q);
}

/* ------------------------------------------------------------------ */
/* Test 4: eq_dropped resets perspective across pushes (no false drops) */
/* ------------------------------------------------------------------ */
static void test_no_false_drops(void)
{
    static EventQueue q;
    eq_init(&q);

    /* Single push + pop � must not record a drop */
    eq_push(&q, "ping");

    char buf[EQ_MAX_EVENT_LEN];
    eq_pop(&q, buf, sizeof(buf));

    CHECK(eq_dropped(&q) == 0,
        "eq_dropped() should be 0 when no overflow has occurred");

    eq_destroy(&q);
}

/* ------------------------------------------------------------------ */
int main(void)
{
    test_push_pop_order();
    test_empty_pop();
    test_overflow();
    test_no_false_drops();

    printf("All checks passed.\n");
    return 0;
}