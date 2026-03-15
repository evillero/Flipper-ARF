#include "fiat_marelli.h"
#include <inttypes.h>
#include <lib/toolbox/manchester_decoder.h>

#define TAG "FiatMarelli"

//   Magneti Marelli BSI keyfob protocol
//   Found on: Fiat Panda, Grande Punto (and possibly other Fiat/Lancia/Alfa ~2003-2012)
//
//   RF: 433.92 MHz, Manchester encoding
//   Two timing variants with identical frame structure:
//     Type A (e.g. Panda):        te_short ~260us, te_long ~520us
//     Type B (e.g. Grande Punto): te_short ~100us, te_long ~200us
//   TE is auto-detected from preamble pulse averaging.
//
//   Preamble: many short-short pairs (alternating TE HIGH/LOW)
//   Gap: ~12x TE LOW
//   Sync: ~8x TE HIGH
//   Data: 103-104 Manchester bits (13 bytes), first 14-16 bits are 0xFFF preamble residue
//   Retransmissions: 7-10 per press
//
//   Frame layout (103-104 bits = 13 bytes):
//     Bytes 0-1:  0xFFFF/0xFFFC preamble residue
//     Bytes 2-5:  Fixed ID / Serial (32 bits)
//     Byte 6:     [Button:4 | Epoch:4]
//                 Button (upper nibble): 0x7=Lock, 0xB=Unlock, 0xD=Trunk
//                 Epoch (lower nibble): 4-bit counter extension (decrements on counter wrap)
//     Byte 7:     [Counter:5 | Scramble:2 | Fixed:1]
//                 Counter: 5-bit plaintext decrementing counter (MSBs of byte)
//                 Scramble: 2 bits dependent on counter/button/epoch
//                 LSB: fixed (1 for Type A, 0 for Type B)
//     Bytes 8-12: Encrypted payload (40 bits)
//                 Fixed bits: bit 37=0, bit 38=1, bit 47=0 (relative to rolling code)
//
//   Full counter: 52 bits = (Epoch << 48) | Rolling_48bit (shared across all buttons)
//   Cipher: proprietary, ~38 effective encrypted bits, weak MSB diffusion

// Preamble: accept short pulses in this range for auto-TE detection
#define FIAT_MARELLI_PREAMBLE_PULSE_MIN 50
#define FIAT_MARELLI_PREAMBLE_PULSE_MAX 350
#define FIAT_MARELLI_PREAMBLE_MIN       80   // Min preamble pulses before gap detection
#define FIAT_MARELLI_MAX_DATA_BITS      104  // Max data bits to collect (13 bytes)
#define FIAT_MARELLI_MIN_DATA_BITS      80   // Min bits for a valid frame
// Gap/sync relative multipliers (applied to auto-detected te_short)
#define FIAT_MARELLI_GAP_TE_MULT        4    // Gap > 4 * te_short
#define FIAT_MARELLI_SYNC_TE_MIN_MULT   4    // Sync >= 4 * te_short
#define FIAT_MARELLI_SYNC_TE_MAX_MULT   12   // Sync <= 12 * te_short
// Fallback for retransmission detection (no preamble)
#define FIAT_MARELLI_RETX_GAP_MIN       5000 // Direct gap detection from Reset (us)
#define FIAT_MARELLI_RETX_SYNC_MIN      400  // Retx sync min (us)
#define FIAT_MARELLI_RETX_SYNC_MAX      2800 // Retx sync max (us)
// TE boundary for variant classification
#define FIAT_MARELLI_TE_TYPE_AB_BOUNDARY 180  // < 180 = Type B, >= 180 = Type A

static const SubGhzBlockConst subghz_protocol_fiat_marelli_const = {
    .te_short = 260,
    .te_long = 520,
    .te_delta = 80,
    .min_count_bit_for_found = 80,
};

struct SubGhzProtocolDecoderFiatMarelli {
    SubGhzProtocolDecoderBase base;
    SubGhzBlockDecoder decoder;
    SubGhzBlockGeneric generic;
    ManchesterState manchester_state;
    uint8_t decoder_state;
    uint16_t preamble_count;
    uint8_t raw_data[13];    // Up to 104 bits (13 bytes)
    uint8_t bit_count;
    uint32_t extra_data;     // Bits beyond first 64, right-aligned
    uint32_t te_last;
    // Auto-TE detection
    uint32_t te_sum;         // Sum of preamble pulse durations
    uint16_t te_count;       // Number of preamble pulses averaged
    uint32_t te_detected;    // Auto-detected te_short (0 = not yet detected)
};

struct SubGhzProtocolEncoderFiatMarelli {
    SubGhzProtocolEncoderBase base;
    SubGhzProtocolBlockEncoder encoder;
    SubGhzBlockGeneric generic;
};

typedef enum {
    FiatMarelliDecoderStepReset = 0,
    FiatMarelliDecoderStepPreamble = 1,
    FiatMarelliDecoderStepSync = 2,
    FiatMarelliDecoderStepData = 3,
    FiatMarelliDecoderStepRetxSync = 4,  // Waiting for sync after large gap (no preamble)
} FiatMarelliDecoderStep;

// ============================================================================
// PROTOCOL INTERFACE DEFINITIONS
// ============================================================================

const SubGhzProtocolDecoder subghz_protocol_fiat_marelli_decoder = {
    .alloc = subghz_protocol_decoder_fiat_marelli_alloc,
    .free = subghz_protocol_decoder_fiat_marelli_free,
    .feed = subghz_protocol_decoder_fiat_marelli_feed,
    .reset = subghz_protocol_decoder_fiat_marelli_reset,
    .get_hash_data = subghz_protocol_decoder_fiat_marelli_get_hash_data,
    .serialize = subghz_protocol_decoder_fiat_marelli_serialize,
    .deserialize = subghz_protocol_decoder_fiat_marelli_deserialize,
    .get_string = subghz_protocol_decoder_fiat_marelli_get_string,
};

const SubGhzProtocolEncoder subghz_protocol_fiat_marelli_encoder = {
    .alloc = subghz_protocol_encoder_fiat_marelli_alloc,
    .free = subghz_protocol_encoder_fiat_marelli_free,
    .deserialize = subghz_protocol_encoder_fiat_marelli_deserialize,
    .stop = subghz_protocol_encoder_fiat_marelli_stop,
    .yield = subghz_protocol_encoder_fiat_marelli_yield,
};

const SubGhzProtocol subghz_protocol_fiat_marelli = {
    .name = FIAT_MARELLI_PROTOCOL_NAME,
    .type = SubGhzProtocolTypeDynamic,
    .flag = SubGhzProtocolFlag_433 | SubGhzProtocolFlag_FM | SubGhzProtocolFlag_Decodable |
            SubGhzProtocolFlag_Load | SubGhzProtocolFlag_Save,
    .decoder = &subghz_protocol_fiat_marelli_decoder,
    .encoder = &subghz_protocol_fiat_marelli_encoder,
};

// ============================================================================
// ENCODER STUBS (decode-only protocol)
// ============================================================================

void* subghz_protocol_encoder_fiat_marelli_alloc(SubGhzEnvironment* environment) {
    UNUSED(environment);
    SubGhzProtocolEncoderFiatMarelli* instance = calloc(1, sizeof(SubGhzProtocolEncoderFiatMarelli));
    furi_check(instance);
    instance->base.protocol = &subghz_protocol_fiat_marelli;
    instance->generic.protocol_name = instance->base.protocol->name;
    instance->encoder.is_running = false;
    return instance;
}

void subghz_protocol_encoder_fiat_marelli_free(void* context) {
    furi_check(context);
    SubGhzProtocolEncoderFiatMarelli* instance = context;
    free(instance);
}

SubGhzProtocolStatus
    subghz_protocol_encoder_fiat_marelli_deserialize(void* context, FlipperFormat* flipper_format) {
    UNUSED(context);
    UNUSED(flipper_format);
    return SubGhzProtocolStatusError;
}

void subghz_protocol_encoder_fiat_marelli_stop(void* context) {
    furi_check(context);
    SubGhzProtocolEncoderFiatMarelli* instance = context;
    instance->encoder.is_running = false;
}

LevelDuration subghz_protocol_encoder_fiat_marelli_yield(void* context) {
    UNUSED(context);
    return level_duration_reset();
}

// ============================================================================
// DECODER IMPLEMENTATION
// ============================================================================

// Helper: rebuild raw_data[] from generic.data + extra_data
static void fiat_marelli_rebuild_raw_data(SubGhzProtocolDecoderFiatMarelli* instance) {
    memset(instance->raw_data, 0, sizeof(instance->raw_data));

    // First 64 bits from generic.data
    uint64_t key = instance->generic.data;
    for(int i = 0; i < 8; i++) {
        instance->raw_data[i] = (uint8_t)(key >> (56 - i * 8));
    }

    // Remaining bits from extra_data (right-aligned)
    uint8_t extra_bits =
        instance->generic.data_count_bit > 64 ? (instance->generic.data_count_bit - 64) : 0;
    for(uint8_t i = 0; i < extra_bits && i < 32; i++) {
        uint8_t byte_idx = 8 + (i / 8);
        uint8_t bit_pos = 7 - (i % 8);
        if(instance->extra_data & (1UL << (extra_bits - 1 - i))) {
            instance->raw_data[byte_idx] |= (1 << bit_pos);
        }
    }

    instance->bit_count = instance->generic.data_count_bit;
}

// Helper: prepare data collection state for Manchester decoding
static void fiat_marelli_prepare_data(SubGhzProtocolDecoderFiatMarelli* instance) {
    instance->bit_count = 0;
    instance->extra_data = 0;
    instance->generic.data = 0;
    memset(instance->raw_data, 0, sizeof(instance->raw_data));
    manchester_advance(
        instance->manchester_state,
        ManchesterEventReset,
        &instance->manchester_state,
        NULL);
    instance->decoder_state = FiatMarelliDecoderStepData;
}

void* subghz_protocol_decoder_fiat_marelli_alloc(SubGhzEnvironment* environment) {
    UNUSED(environment);
    SubGhzProtocolDecoderFiatMarelli* instance =
        calloc(1, sizeof(SubGhzProtocolDecoderFiatMarelli));
    furi_check(instance);
    instance->base.protocol = &subghz_protocol_fiat_marelli;
    instance->generic.protocol_name = instance->base.protocol->name;
    return instance;
}

void subghz_protocol_decoder_fiat_marelli_free(void* context) {
    furi_check(context);
    SubGhzProtocolDecoderFiatMarelli* instance = context;
    free(instance);
}

void subghz_protocol_decoder_fiat_marelli_reset(void* context) {
    furi_check(context);
    SubGhzProtocolDecoderFiatMarelli* instance = context;
    instance->decoder_state = FiatMarelliDecoderStepReset;
    instance->preamble_count = 0;
    instance->bit_count = 0;
    instance->extra_data = 0;
    instance->te_last = 0;
    instance->te_sum = 0;
    instance->te_count = 0;
    instance->te_detected = 0;
    instance->generic.data = 0;
    memset(instance->raw_data, 0, sizeof(instance->raw_data));
    instance->manchester_state = ManchesterStateMid1;
}

void subghz_protocol_decoder_fiat_marelli_feed(void* context, bool level, uint32_t duration) {
    furi_check(context);
    SubGhzProtocolDecoderFiatMarelli* instance = context;

    // Use auto-detected TE if available, otherwise fall back to defaults
    uint32_t te_short = instance->te_detected ? instance->te_detected
                                              : (uint32_t)subghz_protocol_fiat_marelli_const.te_short;
    uint32_t te_long = te_short * 2;
    // Delta must be wide enough for asymmetric timing (Type B pos~140us neg~68us)
    // but < te_short/2 to avoid short/long overlap
    uint32_t te_delta = te_short * 45 / 100;
    if(te_delta < 30) te_delta = 30;
    uint32_t diff;

    switch(instance->decoder_state) {
    case FiatMarelliDecoderStepReset:
        if(level) {
            // Check for preamble-like short HIGH pulse (50-350us range)
            if(duration >= FIAT_MARELLI_PREAMBLE_PULSE_MIN &&
               duration <= FIAT_MARELLI_PREAMBLE_PULSE_MAX) {
                instance->decoder_state = FiatMarelliDecoderStepPreamble;
                instance->preamble_count = 1;
                instance->te_sum = duration;
                instance->te_count = 1;
                instance->te_last = duration;
            }
        } else {
            // Large LOW gap without preamble -> retransmission path
            if(duration > FIAT_MARELLI_RETX_GAP_MIN) {
                instance->decoder_state = FiatMarelliDecoderStepRetxSync;
                instance->te_last = duration;
            }
        }
        break;

    case FiatMarelliDecoderStepPreamble:
        if(duration >= FIAT_MARELLI_PREAMBLE_PULSE_MIN &&
           duration <= FIAT_MARELLI_PREAMBLE_PULSE_MAX) {
            // Short pulse (HIGH or LOW) - preamble continues
            instance->preamble_count++;
            instance->te_sum += duration;
            instance->te_count++;
            instance->te_last = duration;
        } else if(!level) {
            // Non-short LOW pulse - could be gap after preamble
            if(instance->preamble_count >= FIAT_MARELLI_PREAMBLE_MIN && instance->te_count > 0) {
                // Compute auto-detected TE from preamble average
                instance->te_detected = instance->te_sum / instance->te_count;
                uint32_t gap_threshold = instance->te_detected * FIAT_MARELLI_GAP_TE_MULT;

                if(duration > gap_threshold) {
                    // Gap detected - wait for sync
                    instance->decoder_state = FiatMarelliDecoderStepSync;
                    instance->te_last = duration;
                } else {
                    instance->decoder_state = FiatMarelliDecoderStepReset;
                }
            } else {
                instance->decoder_state = FiatMarelliDecoderStepReset;
            }
        } else {
            // Non-short HIGH pulse during preamble - reset
            instance->decoder_state = FiatMarelliDecoderStepReset;
        }
        break;

    case FiatMarelliDecoderStepSync: {
        // Expect sync HIGH pulse (scaled to detected TE)
        uint32_t sync_min = instance->te_detected * FIAT_MARELLI_SYNC_TE_MIN_MULT;
        uint32_t sync_max = instance->te_detected * FIAT_MARELLI_SYNC_TE_MAX_MULT;

        if(level && duration >= sync_min && duration <= sync_max) {
            fiat_marelli_prepare_data(instance);
            instance->te_last = duration;
        } else {
            instance->decoder_state = FiatMarelliDecoderStepReset;
        }
        break;
    }

    case FiatMarelliDecoderStepRetxSync:
        // Retransmission path: expect sync HIGH pulse after large gap
        // Use broad range since we don't know TE yet
        if(level && duration >= FIAT_MARELLI_RETX_SYNC_MIN &&
           duration <= FIAT_MARELLI_RETX_SYNC_MAX) {
            // Auto-detect TE from sync pulse (sync is ~8x TE)
            if(!instance->te_detected) {
                instance->te_detected = duration / 8;
                // Clamp to reasonable range
                if(instance->te_detected < 70) instance->te_detected = 100;
                if(instance->te_detected > 350) instance->te_detected = 260;
            }
            fiat_marelli_prepare_data(instance);
            instance->te_last = duration;
        } else {
            instance->decoder_state = FiatMarelliDecoderStepReset;
        }
        break;

    case FiatMarelliDecoderStepData: {
        ManchesterEvent event = ManchesterEventReset;
        bool frame_complete = false;

        // Classify duration as short or long Manchester edge using detected TE
        diff = (duration > te_short) ? (duration - te_short) : (te_short - duration);
        if(diff < te_delta) {
            event = level ? ManchesterEventShortLow : ManchesterEventShortHigh;
        } else {
            diff = (duration > te_long) ? (duration - te_long) : (te_long - duration);
            if(diff < te_delta) {
                event = level ? ManchesterEventLongLow : ManchesterEventLongHigh;
            }
        }

        if(event != ManchesterEventReset) {
            bool data_bit;
            if(manchester_advance(
                   instance->manchester_state,
                   event,
                   &instance->manchester_state,
                   &data_bit)) {
                uint32_t new_bit = data_bit ? 1 : 0;

                if(instance->bit_count < FIAT_MARELLI_MAX_DATA_BITS) {
                    uint8_t byte_idx = instance->bit_count / 8;
                    uint8_t bit_pos = 7 - (instance->bit_count % 8);
                    if(new_bit) {
                        instance->raw_data[byte_idx] |= (1 << bit_pos);
                    }
                }

                if(instance->bit_count < 64) {
                    instance->generic.data = (instance->generic.data << 1) | new_bit;
                } else {
                    instance->extra_data = (instance->extra_data << 1) | new_bit;
                }

                instance->bit_count++;

                if(instance->bit_count >= FIAT_MARELLI_MAX_DATA_BITS) {
                    frame_complete = true;
                }
            }
        } else {
            if(instance->bit_count >= FIAT_MARELLI_MIN_DATA_BITS) {
                frame_complete = true;
            } else {
                instance->decoder_state = FiatMarelliDecoderStepReset;
            }
        }

        if(frame_complete) {
            instance->generic.data_count_bit = instance->bit_count;

            // Frame layout: bytes 0-1 are preamble residue (0xFFFF or 0xFFFC)
            // Bytes 2-5: Fixed ID (serial)
            // Byte 6: [Button:4 | Epoch:4]
            // Byte 7: [Counter:5 | Scramble:2 | Fixed:1]
            // Bytes 8-12: Encrypted payload (40 bits)
            instance->generic.serial =
                ((uint32_t)instance->raw_data[2] << 24) |
                ((uint32_t)instance->raw_data[3] << 16) |
                ((uint32_t)instance->raw_data[4] << 8) |
                ((uint32_t)instance->raw_data[5]);
            instance->generic.btn = (instance->raw_data[6] >> 4) & 0xF;
            // cnt: 5-bit plaintext counter from byte 7 upper bits
            instance->generic.cnt = (instance->raw_data[7] >> 3) & 0x1F;

            const char* variant = (instance->te_detected &&
                                   instance->te_detected < FIAT_MARELLI_TE_TYPE_AB_BOUNDARY)
                                      ? "B"
                                      : "A";

            FURI_LOG_I(
                TAG,
                "Type%s TE:%lu %db Sn:%08lX Btn:0x%X Ep:%X Ctr:%lu Roll:%02X%02X%02X%02X%02X%02X",
                variant,
                instance->te_detected ? instance->te_detected : te_short,
                instance->bit_count,
                instance->generic.serial,
                instance->generic.btn,
                instance->raw_data[6] & 0xF,
                instance->generic.cnt,
                instance->raw_data[7],
                instance->raw_data[8],
                instance->raw_data[9],
                instance->raw_data[10],
                instance->raw_data[11],
                instance->raw_data[12]);

            if(instance->base.callback) {
                instance->base.callback(&instance->base, instance->base.context);
            }

            instance->decoder_state = FiatMarelliDecoderStepReset;
        }

        instance->te_last = duration;
        break;
    }
    }
}

uint8_t subghz_protocol_decoder_fiat_marelli_get_hash_data(void* context) {
    furi_check(context);
    SubGhzProtocolDecoderFiatMarelli* instance = context;
    SubGhzBlockDecoder decoder = {
        .decode_data = instance->generic.data,
        .decode_count_bit =
            instance->generic.data_count_bit > 64 ? 64 : instance->generic.data_count_bit,
    };
    return subghz_protocol_blocks_get_hash_data(&decoder, (decoder.decode_count_bit / 8) + 1);
}

SubGhzProtocolStatus subghz_protocol_decoder_fiat_marelli_serialize(
    void* context,
    FlipperFormat* flipper_format,
    SubGhzRadioPreset* preset) {
    furi_check(context);
    SubGhzProtocolDecoderFiatMarelli* instance = context;

    SubGhzProtocolStatus ret =
        subghz_block_generic_serialize(&instance->generic, flipper_format, preset);

    if(ret == SubGhzProtocolStatusOk) {
        // Save extra data (bits 64+ right-aligned in uint32_t)
        flipper_format_write_uint32(flipper_format, "Extra", &instance->extra_data, 1);

        // Save total bit count explicitly (generic serialize also saves it, but Extra needs context)
        uint32_t extra_bits = instance->generic.data_count_bit > 64
                                  ? (instance->generic.data_count_bit - 64)
                                  : 0;
        flipper_format_write_uint32(flipper_format, "Extra_bits", &extra_bits, 1);

        // Save detected TE for variant identification on reload
        uint32_t te = instance->te_detected;
        flipper_format_write_uint32(flipper_format, "TE", &te, 1);
    }

    return ret;
}

SubGhzProtocolStatus subghz_protocol_decoder_fiat_marelli_deserialize(
    void* context,
    FlipperFormat* flipper_format) {
    furi_check(context);
    SubGhzProtocolDecoderFiatMarelli* instance = context;

    SubGhzProtocolStatus ret =
        subghz_block_generic_deserialize(&instance->generic, flipper_format);

    if(ret == SubGhzProtocolStatusOk) {
        uint32_t extra = 0;
        if(flipper_format_read_uint32(flipper_format, "Extra", &extra, 1)) {
            instance->extra_data = extra;
        }

        uint32_t te = 0;
        if(flipper_format_read_uint32(flipper_format, "TE", &te, 1)) {
            instance->te_detected = te;
        }

        fiat_marelli_rebuild_raw_data(instance);
    }

    return ret;
}

static const char* fiat_marelli_button_name(uint8_t btn) {
    switch(btn) {
    case 0x7:
        return "Lock";
    case 0xB:
        return "Unlock";
    case 0xD:
        return "Trunk";
    default:
        return "Unknown";
    }
}

void subghz_protocol_decoder_fiat_marelli_get_string(void* context, FuriString* output) {
    furi_check(context);
    SubGhzProtocolDecoderFiatMarelli* instance = context;

    uint8_t total_bytes = (instance->bit_count + 7) / 8;
    if(total_bytes > 13) total_bytes = 13;

    uint8_t epoch = instance->raw_data[6] & 0xF;
    uint8_t counter = (instance->raw_data[7] >> 3) & 0x1F;

    const char* variant = (instance->te_detected &&
                           instance->te_detected < FIAT_MARELLI_TE_TYPE_AB_BOUNDARY)
                              ? "B"
                              : "A";

    furi_string_cat_printf(
        output,
        "%s %dbit Type%s\r\n"
        "Sn:%08lX Btn:%s(0x%X)\r\n"
        "Ep:%X Ctr:%d Roll:%02X%02X%02X%02X%02X%02X\r\n"
        "Data:",
        instance->generic.protocol_name,
        instance->bit_count,
        variant,
        instance->generic.serial,
        fiat_marelli_button_name(instance->generic.btn),
        instance->generic.btn,
        epoch,
        counter,
        instance->raw_data[7],
        instance->raw_data[8],
        instance->raw_data[9],
        (total_bytes > 10) ? instance->raw_data[10] : 0,
        (total_bytes > 11) ? instance->raw_data[11] : 0,
        (total_bytes > 12) ? instance->raw_data[12] : 0);

    for(uint8_t i = 0; i < total_bytes; i++) {
        furi_string_cat_printf(output, "%02X", instance->raw_data[i]);
    }
    furi_string_cat_printf(output, "\r\n");
}
