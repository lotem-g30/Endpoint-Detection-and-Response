#pragma once
#include <windows.h>
#include "event_queue.h"

#ifdef __cplusplus
extern "C" {
#endif

extern EventQueue g_queue;

void hooks_install(void);
void hooks_uninstall(void);

#ifdef __cplusplus
}
#endif
