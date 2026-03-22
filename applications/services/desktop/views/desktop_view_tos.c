#include <furi.h>
#include "desktop_view_tos.h"

struct DesktopViewTos {
    View* view;
    DesktopViewTosCallback callback;
    void* context;
};

static void desktop_view_tos_draw(Canvas* canvas, void* model) {
    UNUSED(model);
    canvas_clear(canvas);

    static const uint8_t mario_bits[] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xcc,0x00,0x00,0x82,0x01,0x00,
        0xc1,0x00,0x00,0xe1,0x07,0x80,0x09,0x08,0x40,0x46,0x07,0x40,0x42,0x03,0x40,0x08,
        0x04,0x80,0x30,0x04,0x00,0xf1,0x04,0x80,0x82,0x07,0x20,0xfc,0x00,0x30,0x7e,0x00,
        0x10,0x91,0x00,0x10,0xa0,0x02,0xe0,0x20,0x05,0x60,0x31,0x07,0xf0,0xfb,0x03,0xf0,
        0xe3,0x00,0xe8,0xe9,0x00,0x08,0xfe,0x00,0x1c,0x7c,0x01,0xf4,0x1f,0x06,0xe4,0x13,
        0x0e,0x84,0x90,0x09,0x84,0x40,0x08,0x88,0x20,0x06,0x70,0xe0,0x03,0x00,0x00,0x00};

    canvas_draw_xbm(canvas, 105, 0, 22, 32, mario_bits);

    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 2, 11, "Term of use:");

    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str(canvas, 3, 22, "Authorize RF research");
    canvas_draw_str(canvas, 3, 30, "use ONLY. Unauthorized");
    canvas_draw_str(canvas, 3, 39, "use is prohibited.");
    canvas_draw_str(canvas, 2, 61, "Back=Shutdown");
    canvas_draw_str(canvas, 80, 62, "Ok=Accept");
}

static bool desktop_view_tos_input(InputEvent* event, void* context) {
    furi_assert(event);
    DesktopViewTos* instance = context;

    if(event->type == InputTypeShort) {
        if(event->key == InputKeyOk) {
            instance->callback(DesktopTosAccepted, instance->context);
            return true;
        } else if(event->key == InputKeyBack) {
            instance->callback(DesktopTosDeclined, instance->context);
            return true;
        }
    }
    return true;
}

DesktopViewTos* desktop_view_tos_alloc(void) {
    DesktopViewTos* instance = malloc(sizeof(DesktopViewTos));
    instance->view = view_alloc();
    view_set_context(instance->view, instance);
    view_set_draw_callback(instance->view, desktop_view_tos_draw);
    view_set_input_callback(instance->view, desktop_view_tos_input);
    return instance;
}

void desktop_view_tos_free(DesktopViewTos* instance) {
    furi_assert(instance);
    view_free(instance->view);
    free(instance);
}

View* desktop_view_tos_get_view(DesktopViewTos* instance) {
    furi_assert(instance);
    return instance->view;
}

void desktop_view_tos_set_callback(
    DesktopViewTos* instance,
    DesktopViewTosCallback callback,
    void* context) {
    furi_assert(instance);
    furi_assert(callback);
    instance->callback = callback;
    instance->context = context;
}
