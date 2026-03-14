#include "rolljam_receiver.h"
#include <furi_hal_subghz.h>
#include <furi_hal_rtc.h>

#define CC_IOCFG0   0x02
#define CC_FIFOTHR  0x03
#define CC_MDMCFG4  0x10
#define CC_MDMCFG3  0x11
#define CC_MDMCFG2  0x12
#define CC_MDMCFG1  0x13
#define CC_MDMCFG0  0x14
#define CC_DEVIATN  0x15
#define CC_MCSM0    0x18
#define CC_FOCCFG   0x19
#define CC_AGCCTRL2 0x1B
#define CC_AGCCTRL1 0x1C
#define CC_AGCCTRL0 0x1D
#define CC_FREND0   0x22
#define CC_FSCAL3   0x23
#define CC_FSCAL2   0x24
#define CC_FSCAL1   0x25
#define CC_FSCAL0   0x26

// ============================================================
// Presets
// ============================================================

static const uint8_t preset_ook_rx[] = {
    CC_IOCFG0,   0x0D,
    CC_FIFOTHR,  0x47,
    CC_MDMCFG4,  0xD7,  // RX BW ~100kHz — wider than jam offset rejection but better sensitivity
    CC_MDMCFG3,  0x32,
    CC_MDMCFG2,  0x30,
    CC_MDMCFG1,  0x00,
    CC_MDMCFG0,  0x00,
    CC_DEVIATN,  0x47,
    CC_MCSM0,    0x18,
    CC_FOCCFG,   0x16,
    CC_AGCCTRL2, 0x43,  // MAX_DVGA_GAIN=01, MAX_LNA_GAIN=max, MAGN_TARGET=011 — more sensitive
    CC_AGCCTRL1, 0x40,  // CS_REL_THR relative threshold
    CC_AGCCTRL0, 0x91,
    CC_FREND0,   0x11,
    CC_FSCAL3,   0xEA,
    CC_FSCAL2,   0x2A,
    CC_FSCAL1,   0x00,
    CC_FSCAL0,   0x1F,
    0x00, 0x00
};

static const uint8_t preset_fsk_rx[] = {
    CC_IOCFG0,   0x0D,
    CC_FIFOTHR,  0x47,
    CC_MDMCFG4,  0xE7,
    CC_MDMCFG3,  0x32,
    CC_MDMCFG2,  0x00,
    CC_MDMCFG1,  0x00,
    CC_MDMCFG0,  0x00,
    CC_DEVIATN,  0x15,
    CC_MCSM0,    0x18,
    CC_FOCCFG,   0x16,
    CC_AGCCTRL2, 0x07,
    CC_AGCCTRL1, 0x00,
    CC_AGCCTRL0, 0x91,
    CC_FREND0,   0x10,
    CC_FSCAL3,   0xEA,
    CC_FSCAL2,   0x2A,
    CC_FSCAL1,   0x00,
    CC_FSCAL0,   0x1F,
    0x00, 0x00
};

static const uint8_t preset_ook_tx[] = {
    CC_IOCFG0,   0x0D,
    CC_FIFOTHR,  0x47,
    CC_MDMCFG4,  0x8C,
    CC_MDMCFG3,  0x32,
    CC_MDMCFG2,  0x30,
    CC_MDMCFG1,  0x00,
    CC_MDMCFG0,  0x00,
    CC_DEVIATN,  0x47,
    CC_MCSM0,    0x18,
    CC_FOCCFG,   0x16,
    CC_AGCCTRL2, 0x07,
    CC_AGCCTRL1, 0x00,
    CC_AGCCTRL0, 0x91,
    CC_FREND0,   0x11,
    CC_FSCAL3,   0xEA,
    CC_FSCAL2,   0x2A,
    CC_FSCAL1,   0x00,
    CC_FSCAL0,   0x1F,
    0x00, 0x00
};

static const uint8_t preset_fsk_tx_238[] = {
    CC_IOCFG0,   0x0D,
    CC_FIFOTHR,  0x47,
    CC_MDMCFG4,  0x8C,
    CC_MDMCFG3,  0x32,
    CC_MDMCFG2,  0x00,
    CC_MDMCFG1,  0x00,
    CC_MDMCFG0,  0x00,
    CC_DEVIATN,  0x15,
    CC_MCSM0,    0x18,
    CC_FOCCFG,   0x16,
    CC_AGCCTRL2, 0x07,
    CC_AGCCTRL1, 0x00,
    CC_AGCCTRL0, 0x91,
    CC_FREND0,   0x10,
    CC_FSCAL3,   0xEA,
    CC_FSCAL2,   0x2A,
    CC_FSCAL1,   0x00,
    CC_FSCAL0,   0x1F,
    0x00, 0x00
};

static const uint8_t preset_fsk_tx_476[] = {
    CC_IOCFG0,   0x0D,
    CC_FIFOTHR,  0x47,
    CC_MDMCFG4,  0x8C,
    CC_MDMCFG3,  0x32,
    CC_MDMCFG2,  0x00,
    CC_MDMCFG1,  0x00,
    CC_MDMCFG0,  0x00,
    CC_DEVIATN,  0x47,
    CC_MCSM0,    0x18,
    CC_FOCCFG,   0x16,
    CC_AGCCTRL2, 0x07,
    CC_AGCCTRL1, 0x00,
    CC_AGCCTRL0, 0x91,
    CC_FREND0,   0x10,
    CC_FSCAL3,   0xEA,
    CC_FSCAL2,   0x2A,
    CC_FSCAL1,   0x00,
    CC_FSCAL0,   0x1F,
    0x00, 0x00
};

// ============================================================
// Capture state machine
// ============================================================

#define MIN_PULSE_US       50
#define MAX_PULSE_US       32767  // int16_t max — covers all keyfob pulse widths
#define SILENCE_GAP_US     50000  // 50ms gap = real end of frame for all keyfob types
#define MIN_FRAME_PULSES   20     // Some keyfobs have short frames
#define AUTO_ACCEPT_PULSES 300    // Need more pulses before auto-accept

// Tolerance for jammer pattern detection (microseconds)
#define JAM_PATTERN_TOLERANCE 120

static bool rolljam_is_jammer_pattern(RawSignal* s) {
    if(s->size < 20) return false;
    int16_t first = s->data[0];
    int16_t abs_first = first > 0 ? first : -first;
    int matches = 0;
    for(size_t i = 0; i < s->size; i++) {
        int16_t val = s->data[i];
        int16_t abs_val = val > 0 ? val : -val;
        int diff = abs_val - abs_first;
        if(diff < 0) diff = -diff;
        if(diff < JAM_PATTERN_TOLERANCE) {
            matches++;
        }
    }
    return (matches > (int)(s->size * 8 / 10));
}

typedef enum {
    CapWaiting,
    CapRecording,
    CapDone,
} CapState;

static volatile CapState cap_state;
static volatile int cap_valid_count;
static volatile int cap_total_count;
static volatile bool cap_target_first;
static volatile uint32_t cap_callback_count;
static volatile float cap_rssi_baseline;

static void capture_rx_callback(bool level, uint32_t duration, void* context) {
    RollJamApp* app = context;

    if(!app->raw_capture_active) return;
    if(cap_state == CapDone) return;

    cap_callback_count++;

    RawSignal* target;
    if(cap_target_first) {
        target = &app->signal_first;
        if(target->valid) return;
    } else {
        target = &app->signal_second;
        if(target->valid) return;
    }

    uint32_t dur = duration;
    // Check silence gap BEFORE clamping so 50ms gaps are detected correctly
    // Clamp only affects stored sample value, not gap detection
    bool is_silence = (dur > SILENCE_GAP_US);
    if(dur > 32767) dur = 32767;

    switch(cap_state) {
    case CapWaiting:
        if(dur >= MIN_PULSE_US && dur <= MAX_PULSE_US) {
            target->size = 0;
            cap_valid_count = 0;
            cap_total_count = 0;
            cap_state = CapRecording;

            int16_t s = level ? (int16_t)dur : -(int16_t)dur;
            target->data[target->size++] = s;
            cap_valid_count++;
            cap_total_count++;
        }
        break;

    case CapRecording:
        if(target->size >= RAW_SIGNAL_MAX_SIZE) {
            if(cap_valid_count >= MIN_FRAME_PULSES) {
                cap_state = CapDone;
            } else {
                target->size = 0;
                cap_valid_count = 0;
                cap_total_count = 0;
                cap_state = CapWaiting;
            }
            return;
        }

        if(is_silence) {
            if(cap_valid_count >= MIN_FRAME_PULSES) {
                if(target->size < RAW_SIGNAL_MAX_SIZE) {
                    int16_t s = level ? (int16_t)32767 : -32767;
                    target->data[target->size++] = s;
                }
                cap_state = CapDone;
            } else {
                target->size = 0;
                cap_valid_count = 0;
                cap_total_count = 0;
                cap_state = CapWaiting;
            }
            return;
        }

        {
            int16_t s = level ? (int16_t)dur : -(int16_t)dur;
            target->data[target->size++] = s;
            cap_total_count++;

            if(dur >= MIN_PULSE_US && dur <= MAX_PULSE_US) {
                cap_valid_count++;
                if(cap_valid_count >= AUTO_ACCEPT_PULSES) {
                    cap_state = CapDone;
                }
            }
        }
        break;

    case CapDone:
        break;
    }
}

// ============================================================
// Capture start/stop
// ============================================================

void rolljam_capture_start(RollJamApp* app) {
    FURI_LOG_I(TAG, "Capture start: freq=%lu mod=%d", app->frequency, app->mod_index);

    // Full radio reset sequence
    furi_hal_subghz_reset();
    furi_delay_ms(10);
    furi_hal_subghz_idle();
    furi_delay_ms(10);

    const uint8_t* preset;
    switch(app->mod_index) {
    case ModIndex_FM238:
    case ModIndex_FM476:
        preset = preset_fsk_rx;
        break;
    default:
        preset = preset_ook_rx;
        break;
    }

    furi_hal_subghz_load_custom_preset(preset);
    furi_delay_ms(5);

    uint32_t real_freq = furi_hal_subghz_set_frequency(app->frequency);
    FURI_LOG_I(TAG, "Capture: freq set to %lu", real_freq);

    furi_delay_ms(5);

    furi_hal_subghz_rx();
    furi_delay_ms(50);
    cap_rssi_baseline = furi_hal_subghz_get_rssi();
    furi_hal_subghz_idle();
    furi_delay_ms(5);
    FURI_LOG_I(TAG, "Capture: RSSI baseline=%.1f dBm", (double)cap_rssi_baseline);

    cap_state = CapWaiting;
    cap_valid_count = 0;
    cap_total_count = 0;
    cap_callback_count = 0;

    // Determine target
    if(!app->signal_first.valid) {
        cap_target_first = true;
        app->signal_first.size = 0;
        app->signal_first.valid = false;
        FURI_LOG_I(TAG, "Capture target: FIRST signal");
    } else {
        cap_target_first = false;
        app->signal_second.size = 0;
        app->signal_second.valid = false;
        FURI_LOG_I(TAG, "Capture target: SECOND signal (first already valid, size=%d)",
                   app->signal_first.size);
    }

    app->raw_capture_active = true;
    furi_hal_subghz_start_async_rx(capture_rx_callback, app);

    FURI_LOG_I(TAG, "Capture: RX STARTED, active=%d, target_first=%d",
               app->raw_capture_active, cap_target_first);
}

void rolljam_capture_stop(RollJamApp* app) {
    if(!app->raw_capture_active) {
        FURI_LOG_W(TAG, "Capture stop: was not active");
        return;
    }

    app->raw_capture_active = false;

    furi_hal_subghz_stop_async_rx();
    furi_delay_ms(5);
    furi_hal_subghz_idle();
    furi_delay_ms(5);

    FURI_LOG_I(TAG, "Capture stopped. callbacks=%lu capState=%d validCnt=%d totalCnt=%d",
               cap_callback_count, cap_state, cap_valid_count, cap_total_count);
    FURI_LOG_I(TAG, "  Sig1: size=%d valid=%d", app->signal_first.size, app->signal_first.valid);
    FURI_LOG_I(TAG, "  Sig2: size=%d valid=%d", app->signal_second.size, app->signal_second.valid);
}

// ============================================================
// Validation
// ============================================================

bool rolljam_signal_is_valid(RawSignal* signal) {
    if(cap_state != CapDone) {
        // Log every few checks so we can see if callbacks are happening
        static int check_count = 0;
        check_count++;
        if(check_count % 10 == 0) {
            FURI_LOG_D(TAG, "Validate: not done yet, state=%d callbacks=%lu valid=%d total=%d sig_size=%d",
                       cap_state, cap_callback_count, cap_valid_count, cap_total_count, signal->size);
        }
        return false;
    }

    if(signal->size < MIN_FRAME_PULSES) return false;

    // Reject jammer noise: if signal is uniform amplitude, it's our own jam
    if(rolljam_is_jammer_pattern(signal)) {
        FURI_LOG_W(TAG, "Jammer noise ignored (size=%d)", signal->size);
        signal->size = 0;
        cap_state = CapWaiting;
        cap_valid_count = 0;
        cap_total_count = 0;
        return false;
    }

    int good = 0;
    int total = (int)signal->size;

    for(int i = 0; i < total; i++) {
        int16_t val = signal->data[i];
        int16_t abs_val = val > 0 ? val : -val;
        if((int32_t)abs_val >= MIN_PULSE_US) {  // upper bound = clamp at 32767
            good++;
        }
    }

    int ratio_pct = (total > 0) ? ((good * 100) / total) : 0;

    if(ratio_pct > 50 && good >= MIN_FRAME_PULSES) {
        float rssi = furi_hal_subghz_get_rssi();
        float rssi_delta = rssi - cap_rssi_baseline;
        FURI_LOG_I(TAG, "Signal VALID: %d/%d (%d%%) samples=%d rssi=%.1f delta=%.1f",
                   good, total, ratio_pct, total, (double)rssi, (double)rssi_delta);
        if(rssi_delta < 5.0f && rssi < -85.0f) {
            FURI_LOG_W(TAG, "Signal rejected: RSSI too low (%.1f dBm, delta=%.1f)",
                       (double)rssi, (double)rssi_delta);
            signal->size = 0;
            cap_state = CapWaiting;
            cap_valid_count = 0;
            cap_total_count = 0;
            return false;
        }
        return true;
    }

    FURI_LOG_D(TAG, "Signal rejected: %d/%d (%d%%), reset", good, total, ratio_pct);
    signal->size = 0;
    cap_state = CapWaiting;
    cap_valid_count = 0;
    cap_total_count = 0;
    return false;
}

// ============================================================
// Signal cleanup
// ============================================================

void rolljam_signal_cleanup(RawSignal* signal) {
    if(signal->size < MIN_FRAME_PULSES) return;

    int16_t* cleaned = malloc(RAW_SIGNAL_MAX_SIZE * sizeof(int16_t));
    if(!cleaned) return;
    size_t out = 0;

    size_t start = 0;
    while(start < signal->size) {
        int16_t val = signal->data[start];
        int16_t abs_val = val > 0 ? val : -val;
        if(abs_val >= MIN_PULSE_US) break;
        start++;
    }

    for(size_t i = start; i < signal->size; i++) {
        int16_t val = signal->data[i];
        int16_t abs_val = val > 0 ? val : -val;
        bool is_positive = val > 0;

        if(abs_val < MIN_PULSE_US) {
            if(out > 0) {
                int16_t prev = cleaned[out - 1];
                bool prev_positive = prev > 0;
                int16_t prev_abs = prev > 0 ? prev : -prev;
                if(prev_positive == is_positive) {
                    int32_t merged = (int32_t)prev_abs + abs_val;
                    if(merged > 32767) merged = 32767;
                    cleaned[out - 1] = prev_positive ? (int16_t)merged : -(int16_t)merged;
                }
            }
            continue;
        }

        int32_t q = ((abs_val + 50) / 100) * 100;
        if(q < MIN_PULSE_US) q = MIN_PULSE_US;
        if(q > 32767) q = 32767;
        int16_t quantized = (int16_t)q;

        if(out < RAW_SIGNAL_MAX_SIZE) {
            cleaned[out++] = is_positive ? quantized : -quantized;
        }
    }

    while(out > 0) {
        int16_t last = cleaned[out - 1];
        int16_t abs_last = last > 0 ? last : -last;
        if(abs_last >= MIN_PULSE_US && abs_last < 32767) break;
        out--;
    }

    if(out >= MIN_FRAME_PULSES) {
        size_t orig = signal->size;
        memcpy(signal->data, cleaned, out * sizeof(int16_t));
        signal->size = out;
        FURI_LOG_I(TAG, "Cleanup: %d -> %d samples", (int)orig, (int)out);
    }

    free(cleaned);
}

// ============================================================
// TX
// ============================================================

typedef struct {
    const int16_t* data;
    size_t size;
    volatile size_t index;
} TxCtx;

static TxCtx g_tx;

static LevelDuration tx_feed(void* context) {
    UNUSED(context);
    if(g_tx.index >= g_tx.size) return level_duration_reset();

    int16_t sample = g_tx.data[g_tx.index++];
    bool level = (sample > 0);
    uint32_t dur = (uint32_t)(sample > 0 ? sample : -sample);

    return level_duration_make(level, dur);
}

void rolljam_transmit_signal(RollJamApp* app, RawSignal* signal) {
    if(!signal->valid || signal->size == 0) {
        FURI_LOG_E(TAG, "TX: no valid signal");
        return;
    }

    FURI_LOG_I(TAG, "TX: %d samples at %lu Hz (3x)", signal->size, app->frequency);

    furi_hal_subghz_reset();
    furi_hal_subghz_idle();
    furi_delay_ms(10);

    const uint8_t* tx_preset;
    switch(app->mod_index) {
    case ModIndex_FM238:
        tx_preset = preset_fsk_tx_238;
        break;
    case ModIndex_FM476:
        tx_preset = preset_fsk_tx_476;
        break;
    default:
        tx_preset = preset_ook_tx;
        break;
    }
    furi_hal_subghz_load_custom_preset(tx_preset);
    uint32_t real_freq = furi_hal_subghz_set_frequency(app->frequency);
    FURI_LOG_I(TAG, "TX: freq=%lu", real_freq);

    // Transmit 3 times — improves reliability especially at range
    for(int tx_repeat = 0; tx_repeat < 3; tx_repeat++) {
        g_tx.data = signal->data;
        g_tx.size = signal->size;
        g_tx.index = 0;

        if(!furi_hal_subghz_start_async_tx(tx_feed, NULL)) {
            FURI_LOG_E(TAG, "TX: start failed on repeat %d!", tx_repeat);
            furi_hal_subghz_idle();
            return;
        }

        uint32_t timeout = 0;
        while(!furi_hal_subghz_is_async_tx_complete()) {
            furi_delay_ms(5);
            if(++timeout > 2000) {
                FURI_LOG_E(TAG, "TX: timeout on repeat %d!", tx_repeat);
                break;
            }
        }

        furi_hal_subghz_stop_async_tx();
        FURI_LOG_I(TAG, "TX: repeat %d done (%d/%d)", tx_repeat, g_tx.index, signal->size);

        // Small gap between repeats
        if(tx_repeat < 2) furi_delay_ms(50);
    }

    furi_hal_subghz_idle();
    FURI_LOG_I(TAG, "TX: all repeats done");
}

// ============================================================
// Save
// ============================================================

void rolljam_save_signal(RollJamApp* app, RawSignal* signal) {
    if(!signal->valid || signal->size == 0) {
        FURI_LOG_E(TAG, "Save: no signal");
        return;
    }

    DateTime dt;
    furi_hal_rtc_get_datetime(&dt);

    FuriString* path = furi_string_alloc_printf(
        "/ext/subghz/RJ_%04d%02d%02d_%02d%02d%02d.sub",
        dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second);

    FURI_LOG_I(TAG, "Saving: %s", furi_string_get_cstr(path));

    Storage* storage = furi_record_open(RECORD_STORAGE);
    storage_simply_mkdir(storage, "/ext/subghz");
    File* file = storage_file_alloc(storage);

    if(storage_file_open(file, furi_string_get_cstr(path), FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        FuriString* line = furi_string_alloc();

        furi_string_set(line, "Filetype: Flipper SubGhz RAW File\n");
        storage_file_write(file, furi_string_get_cstr(line), furi_string_size(line));

        furi_string_printf(line, "Version: 1\n");
        storage_file_write(file, furi_string_get_cstr(line), furi_string_size(line));

        furi_string_printf(line, "Frequency: %lu\n", app->frequency);
        storage_file_write(file, furi_string_get_cstr(line), furi_string_size(line));

        const char* pname;
        switch(app->mod_index) {
        case ModIndex_AM270: pname = "FuriHalSubGhzPresetOok270Async"; break;
        case ModIndex_FM238: pname = "FuriHalSubGhzPreset2FSKDev238Async"; break;
        case ModIndex_FM476: pname = "FuriHalSubGhzPreset2FSKDev476Async"; break;
        default: pname = "FuriHalSubGhzPresetOok650Async"; break;
        }

        furi_string_printf(line, "Preset: %s\n", pname);
        storage_file_write(file, furi_string_get_cstr(line), furi_string_size(line));

        furi_string_printf(line, "Protocol: RAW\n");
        storage_file_write(file, furi_string_get_cstr(line), furi_string_size(line));

        size_t i = 0;
        while(i < signal->size) {
            furi_string_set(line, "RAW_Data:");
            size_t end = i + 512;
            if(end > signal->size) end = signal->size;
            for(; i < end; i++) {
                furi_string_cat_printf(line, " %d", signal->data[i]);
            }
            furi_string_cat(line, "\n");
            storage_file_write(file, furi_string_get_cstr(line), furi_string_size(line));
        }

        furi_string_free(line);
        FURI_LOG_I(TAG, "Saved: %d samples", signal->size);
    } else {
        FURI_LOG_E(TAG, "Save failed!");
    }

    storage_file_close(file);
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
    furi_string_free(path);
}
