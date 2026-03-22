#include <power/power_service/power.h>
#include <gui/scene_manager.h>

#include "desktop_scene.h"
#include "../desktop_i.h"
#include "../views/desktop_events.h"
#include "../views/desktop_view_tos.h"

static void desktop_scene_tos_callback(DesktopEvent event, void* context) {
    Desktop* desktop = (Desktop*)context;
    view_dispatcher_send_custom_event(desktop->view_dispatcher, event);
}

void desktop_scene_tos_on_enter(void* context) {
    Desktop* desktop = (Desktop*)context;

    arf_boot_jingle_play();

    gui_set_hide_status_bar(desktop->gui, true);
    desktop_view_tos_set_callback(desktop->tos_view, desktop_scene_tos_callback, desktop);
    view_dispatcher_switch_to_view(desktop->view_dispatcher, DesktopViewIdTos);
}

bool desktop_scene_tos_on_event(void* context, SceneManagerEvent event) {
    Desktop* desktop = (Desktop*)context;
    bool consumed = false;

    if(event.type == SceneManagerEventTypeCustom) {
        switch(event.event) {
        case DesktopTosAccepted:
            scene_manager_previous_scene(desktop->scene_manager);
            consumed = true;
            break;
        case DesktopTosDeclined: {
            Power* power = furi_record_open(RECORD_POWER);
            power_off(power);
            furi_record_close(RECORD_POWER);
            consumed = true;
            break;
        }
        default:
            break;
        }
    }
    return consumed;
}

void desktop_scene_tos_on_exit(void* context) {
    Desktop* desktop = (Desktop*)context;
    arf_boot_jingle_stop();
    gui_set_hide_status_bar(desktop->gui, false);
}
