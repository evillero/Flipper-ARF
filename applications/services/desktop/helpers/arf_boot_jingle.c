#include "arf_boot_jingle.h"

#include <furi.h>
#include <furi_hal_speaker.h>

typedef struct {
    float frequency;
    uint32_t duration_ms;
} ArfBootNote;

static const ArfBootNote arf_boot_jingle[] = {
    {1046.50f, 50},
    {1046.50f, 200},
    {0.0f,     100},
    {783.99f,  300},
    {0.0f,     50},
    {659.26f,  300},
    {0.0f,     50},
    {783.99f,  250},
    {880.00f,  100},
    {880.00f,  100},
    {783.99f,  300},
    {1046.50f, 150},
    {1318.51f, 150},
    {1760.00f, 250},
    {1396.91f, 150},
    {1567.98f, 100},
    {1318.51f, 250},
    {1174.66f, 150},
    {1396.91f, 150},
    {1318.51f, 400},
    {392.00f,  100},
    {523.25f,  300},
    {0.0f,     50},
    {1567.98f, 150},
    {1479.98f, 150},
    {1396.91f, 150},
    {1174.66f, 250},
    {1318.51f, 300},
    {783.99f,  150},
    {1046.50f, 100},
    {1318.51f, 100},
    {783.99f,  100},
    {1046.50f, 100},
    {1318.51f, 150},
    {0.0f,     50},
    {1567.98f, 150},
    {1479.98f, 100},
    {1396.91f, 150},
    {1174.66f, 250},
    {1318.51f, 300},
    {0.0f,     50},
    {2093.00f, 700},
};

static const uint32_t arf_boot_jingle_len =
    sizeof(arf_boot_jingle) / sizeof(arf_boot_jingle[0]);

static FuriThread* jingle_thread = NULL;

static int32_t arf_jingle_thread_cb(void* context) {
    UNUSED(context);

    if(!furi_hal_speaker_acquire(1000)) {
        return 0;
    }

    for(uint32_t i = 0; i < arf_boot_jingle_len; i++) {
        const ArfBootNote* note = &arf_boot_jingle[i];
        if(note->frequency == 0.0f) {
            furi_hal_speaker_stop();
        } else {
            furi_hal_speaker_start(note->frequency, 0.8f);
        }
        furi_delay_ms(note->duration_ms);
    }

    furi_hal_speaker_stop();
    furi_hal_speaker_release();
    return 0;
}

void arf_boot_jingle_play(void) {
    if(jingle_thread != NULL) {
        return;
    }

    jingle_thread = furi_thread_alloc_ex("ArfJingle", 512, arf_jingle_thread_cb, NULL);
    furi_thread_start(jingle_thread);
}

void arf_boot_jingle_stop(void) {
    if(jingle_thread != NULL) {
        furi_thread_join(jingle_thread);
        furi_thread_free(jingle_thread);
        jingle_thread = NULL;
    }
}
