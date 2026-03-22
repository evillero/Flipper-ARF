#pragma once
#include <gui/view.h>
#include "desktop_events.h"

typedef struct DesktopViewTos DesktopViewTos;
typedef void (*DesktopViewTosCallback)(DesktopEvent event, void* context);

DesktopViewTos* desktop_view_tos_alloc(void);
void desktop_view_tos_free(DesktopViewTos* instance);
View* desktop_view_tos_get_view(DesktopViewTos* instance);
void desktop_view_tos_set_callback(
    DesktopViewTos* instance,
    DesktopViewTosCallback callback,
    void* context);
