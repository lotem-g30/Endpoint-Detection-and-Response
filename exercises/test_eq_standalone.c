/*
 * test_eq_standalone.c  —  EventQueue unit test (Section 6.5)
 *
 * Build (from project root):
 *   cl /std:c17 exercises\test_eq_standalone.c src\hook_dll\event_queue.c ^
 *      /Fe:test_eq.exe /I src\hook_dll /I include
 *   test_eq.exe
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

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "event_queue.h"

static int g_failures = 0;

static void check(int condition, const char *msg)
{
    if (!condition) {
        fprintf(stderr, "[FAIL] %s\n", msg);
        g_failures++;
    }
}

static EventQueue q;

int main(void)
{
    eq_init(&q);

    /* Push 5 events */
    for (int i = 0; i < 5; i++) {
        char ev[64];
        snprintf(ev, sizeof(ev), "event_%d", i);
        check(eq_push(&q, ev), "push should succeed");
    }

    /* Pop 5 events and verify order */
    char buf[EQ_MAX_EVENT_LEN];
    for (int i = 0; i < 5; i++) {
        check(eq_pop(&q, buf, sizeof(buf)), "pop should succeed");
        char expected[64];
        snprintf(expected, sizeof(expected), "event_%d", i);
        check(strcmp(buf, expected) == 0, "pop returned wrong event");
        printf("[pop] %s\n", buf);
    }

    /* Empty pop must return false */
    check(!eq_pop(&q, buf, sizeof(buf)), "empty pop should return false");
    printf("[empty pop] returned false: OK\n");

    /*
     * Overflow test: push EQ_CAPACITY items.
     * The queue holds EQ_CAPACITY-1 items; the last push evicts overflow_0.
     * After that: dropped==1, oldest surviving item == overflow_1.
     */
    for (int i = 0; i < EQ_CAPACITY; i++) {
        char ev[64];
        snprintf(ev, sizeof(ev), "overflow_%d", i);
        eq_push(&q, ev);
    }

    check(eq_dropped(&q) == 1, "expected exactly 1 dropped event");
    printf("[overflow] eq_dropped() = %llu\n",
           (unsigned long long)eq_dropped(&q));

    check(eq_pop(&q, buf, sizeof(buf)), "pop after overflow should succeed");
    check(strcmp(buf, "overflow_1") == 0,
          "oldest surviving item should be overflow_1");
    printf("[overflow] oldest surviving item: %s\n", buf);

    eq_destroy(&q);

    if (g_failures == 0) {

        printf("All checks passed.\n");
        return 0;
    }
    fprintf(stderr, "%d check(s) failed.\n", g_failures);
    return 1;
}
