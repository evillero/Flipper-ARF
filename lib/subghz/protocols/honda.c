#include "honda.h"

#include "../blocks/const.h"
#include "../blocks/decoder.h"
#include "../blocks/encoder.h"
#include "../blocks/generic.h"
#include "../blocks/math.h"
#include "../blocks/custom_btn_i.h"

#define TAG "SubGhzProtocolHonda"

static const SubGhzBlockConst subghz_protocol_honda_const = {
    .te_short = HONDA_TE_SHORT,
    .te_long  = HONDA_TE_LONG,
    .te_delta = HONDA_TE_DELTA,
    .min_count_bit_for_found = HONDA_MIN_BITS,
};

/* ============================================================================
 * Pandora rolling-code tables (extracted from firmware @ 0xEFDC)
 * Five 16×16 nibble-substitution tables.
 * ==========================================================================*/
static const uint8_t honda_table_a[16][16] = { HONDA_TABLE_A };
static const uint8_t honda_table_b[16][16] = { HONDA_TABLE_B };
static const uint8_t honda_table_c[16][16] = { HONDA_TABLE_C };
static const uint8_t honda_table_d[16][16] = { HONDA_TABLE_D };
static const uint8_t honda_table_e[16][16] __attribute__((unused)) = { HONDA_TABLE_E };

/* ============================================================================
 * Bit-reverse helpers (mirrors Crypto.Util.Bit_Reverse_Byte @ 0x11AD4)
 * ==========================================================================*/
static inline uint8_t _bit_rev8(uint8_t v) {
    v = (uint8_t)(((v & 0xF0u) >> 4) | ((v & 0x0Fu) << 4));
    v = (uint8_t)(((v & 0xCCu) >> 2) | ((v & 0x33u) << 2));
    v = (uint8_t)(((v & 0xAAu) >> 1) | ((v & 0x55u) << 1));
    return v;
}
static inline uint8_t _bit_rev4(uint8_t v) {
    /* bit-reverse the low 4 bits only */
    return (uint8_t)(_bit_rev8(v & 0x0Fu) >> 4);
}

/* ============================================================================
 * The 10-byte frame buffer has this layout (matching Pandora RAM):
 *   buf[0]  — header byte  (type_b_header<<4 | button)  or  (button<<4 | serial_hi)
 *   buf[1]  — serial[23:16]
 *   buf[2]  — serial[15:8]
 *   buf[3]  — serial[7:0]  / counter cascade
 *   buf[4]  — {serial_low_nibble, counter[23:20]}  (type-B layout)
 *   buf[5]  — counter[19:12]
 *   buf[6]  — counter[11:4]
 *   buf[7]  — {mode_nibble, counter[3:0]}   mode: 0x2 or 0xC
 *   buf[8]  — checksum (nibble-substituted via tables on each TX)
 *   buf[9]  — extra / padding
 *
 * counter bytes are buf[5], buf[6], buf[7] (with low nibble of buf[7] being
 * the LSN of the counter and the high nibble being the mode indicator).
 *
 * The increment algorithm:
 *   1. bit_rev-increment the low nibble of buf[3] (= counter LSN in Pandora)
 *   2. On overflow, cascade to high nibble of buf[3] then to buf[2]
 *   3. Dispatch on mode nibble (buf[7]>>4):
 *      0x2 → use TABLE_A/TABLE_D for checksum nibble substitution
 *      0xC → use TABLE_B/TABLE_D for checksum nibble substitution, flip mode→0x2
 *      (other branches flip mode and recurse similarly)
 *
 * For the Flipper port:
 * plain +1 on the 24-bit counter with nibble-reversed carry, then re-compute
 * the checksum using the appropriate table pair based on the mode nibble.
 * ==========================================================================*/

typedef struct {
    bool     type_b;
    uint8_t  type_b_header;
    uint8_t  button;
    uint32_t serial;
    uint32_t counter;
    uint8_t  checksum;
    uint8_t  mode;   /* high nibble of buf[7]: 0x2 or 0xC */
} HondaFrameData;

/* Build the 10-byte Pandora buffer from a HondaFrameData */
static void _honda_to_buf(const HondaFrameData* f, uint8_t buf[10]) {
    buf[9] = 0x00;
    if(!f->type_b) {
        buf[0] = (uint8_t)((f->button << 4) | ((f->serial >> 24) & 0x0Fu));
        buf[1] = (uint8_t)((f->serial >> 16) & 0xFFu);
        buf[2] = (uint8_t)((f->serial >> 8)  & 0xFFu);
        buf[3] = (uint8_t)( f->serial        & 0xFFu);
        buf[4] = (uint8_t)((f->counter >> 16) & 0xFFu);
        buf[5] = (uint8_t)((f->counter >> 8)  & 0xFFu);
        buf[6] = (uint8_t)( f->counter        & 0xFFu);
        /* buf[7]: mode nibble high | counter LSN low — for Type-A counter is in buf[4..6] */
        buf[7] = (uint8_t)((f->mode & 0x0Fu) << 4);
        buf[8] = f->checksum;
    } else {
        buf[0] = (uint8_t)((f->type_b_header << 4) | (f->button & 0x0Fu));
        buf[1] = (uint8_t)((f->serial >> 20) & 0xFFu);
        buf[2] = (uint8_t)((f->serial >> 12) & 0xFFu);
        buf[3] = (uint8_t)((f->serial >> 4)  & 0xFFu);
        buf[4] = (uint8_t)(((f->serial & 0x0Fu) << 4) | ((f->counter >> 20) & 0x0Fu));
        buf[5] = (uint8_t)((f->counter >> 12) & 0xFFu);
        buf[6] = (uint8_t)((f->counter >> 4)  & 0xFFu);
        buf[7] = (uint8_t)(((f->mode & 0x0Fu) << 4) | (f->counter & 0x0Fu));
        buf[8] = f->checksum;
    }
}

/* Uses TABLE_A (or B) for the low nibble and TABLE_D (or A/B high) for the
 * high nibble of buf[8], indexed by bit-reversed nibbles of buf[3] (counter
 * cascade byte) as per the decompilation. */
static uint8_t _honda_rolling_checksum(const uint8_t buf[10], bool mode_is_c) {
    uint8_t cnt_byte = buf[3];   /* the cascade/index byte Pandora uses */
    uint8_t prev_csum = buf[8];

    /* Choose table pair based on mode (mirrors Pandora's dispatch on buf[7]>>4) */
    const uint8_t (*tbl_lo)[16] = mode_is_c ? honda_table_b : honda_table_a;
    const uint8_t (*tbl_hi)[16] = honda_table_d;
    const uint8_t (*tbl_perm)[16] = honda_table_c;

    uint8_t new_lo = prev_csum & 0x0Fu;
    uint8_t new_hi = (prev_csum >> 4) & 0x0Fu;

    uint8_t idx = _bit_rev8(cnt_byte) & 0x0Fu;

    /* Low nibble substitution (mirrors inner loop in Pandora decompile) */
    for(uint8_t row = 0; row < 16; row++) {
        if(tbl_lo[row][idx] == (prev_csum & 0x0Fu)) {
            new_lo = tbl_perm[row][idx];
            break;
        }
    }

    /* High nibble substitution */
    uint8_t idx_hi = _bit_rev8(cnt_byte >> 4) & 0x0Fu;
    for(uint8_t row = 0; row < 16; row++) {
        if(tbl_hi[row][idx_hi] == ((prev_csum >> 4) & 0x0Fu)) {
            new_hi = tbl_perm[row][idx_hi];
            break;
        }
    }

    return (uint8_t)((new_hi << 4) | new_lo);
}

/* Advance counter by 1 using Pandora's bit-reversed nibble arithmetic.
 * counter increment section @ 0xEFF0-0xF090 */
static void _honda_counter_increment(HondaFrameData* f) {
    uint8_t buf[10];
    _honda_to_buf(f, buf);

    /* Pandora increments buf[3] low nibble with bit-reverse carry */
    uint8_t lo = _bit_rev4(buf[3] & 0x0Fu);
    lo = (lo + 1) & 0x0Fu;
    buf[3] = (buf[3] & 0xF0u) | _bit_rev4(lo);

    /* Carry to high nibble of buf[3] when low overflows (was 0xF) */
    if((f->counter & 0x0Fu) == 0x0Fu) {
        uint8_t hi = _bit_rev4((buf[3] >> 4) & 0x0Fu);
        hi = (hi + 1) & 0x0Fu;
        buf[3] = (buf[3] & 0x0Fu) | (uint8_t)(_bit_rev4(hi) << 4);

        /* Carry to buf[2] */
        if(((f->counter >> 4) & 0x0Fu) == 0x0Fu) {
            uint8_t b2lo = _bit_rev4(buf[2] & 0x0Fu);
            b2lo = (b2lo + 1) & 0x0Fu;
            buf[2] = (buf[2] & 0xF0u) | _bit_rev4(b2lo);
        }
    }

    /* Plain counter +1 */
    f->counter = (f->counter + 1u) & 0x00FFFFFFu;

    /* Mode flip: 0x2 ↔ 0xC (Pandora flips mode nibble each TX cycle) */
    bool mode_was_c = (f->mode == 0xCu);
    f->mode = mode_was_c ? 0x2u : 0xCu;

    /* Recompute checksum using Pandora's table lookup */
    _honda_to_buf(f, buf);
    f->checksum = _honda_rolling_checksum(buf, !mode_was_c);
}

/* ============================================================================
 * Simple XOR checksum (Type-A static, used for initial decode validation)
 * ==========================================================================*/
static uint8_t _honda_xor_checksum(const uint8_t* data) {
    uint8_t c = 0;
    for(uint8_t i = 0; i < 7; i++) c ^= data[i];
    return c;
}

/* ============================================================================
 * Bit helpers
 * ==========================================================================*/
static uint32_t _bits_get(const uint8_t* data, uint8_t start, uint8_t len) {
    uint32_t val = 0;
    for(uint8_t i = 0; i < len; i++) {
        uint8_t byte_idx = (uint8_t)((start + i) / 8u);
        uint8_t bit_idx  = (uint8_t)(7u - ((start + i) % 8u));
        val = (val << 1) | ((data[byte_idx] >> bit_idx) & 1u);
    }
    return val;
}

static void _bits_set(uint8_t* data, uint8_t start, uint8_t len, uint32_t val) {
    if(!len) return;
    for(int8_t i = (int8_t)len - 1; i >= 0; i--) {
        uint8_t pos      = (uint8_t)(start + (uint8_t)i);
        uint8_t byte_idx = (uint8_t)(pos / 8u);
        uint8_t bit_idx  = (uint8_t)(7u - (pos % 8u));
        if(val & 1u)
            data[byte_idx] |= (uint8_t)(1u << bit_idx);
        else
            data[byte_idx] &= (uint8_t)(~(1u << bit_idx));
        val >>= 1;
    }
}

/* ============================================================================
 * Pack / unpack
 * ==========================================================================*/
static uint64_t _honda_pack(const HondaFrameData* f) {
    uint8_t key[8] = {0};
    key[0] = (uint8_t)(((f->type_b ? 1u : 0u) << 7) |
                       ((f->type_b_header & 0x07u) << 4) | (f->button & 0x0Fu));
    key[1] = (uint8_t)((f->serial >> 20) & 0xFFu);
    key[2] = (uint8_t)((f->serial >> 12) & 0xFFu);
    key[3] = (uint8_t)((f->serial >> 4)  & 0xFFu);
    key[4] = (uint8_t)((f->serial & 0x0Fu) << 4);
    key[5] = (uint8_t)((f->counter >> 16) & 0xFFu);
    key[6] = (uint8_t)((f->counter >> 8)  & 0xFFu);
    key[7] = (uint8_t)( f->counter        & 0xFFu);

    uint64_t out = 0;
    for(int i = 0; i < 8; i++) out = (out << 8) | key[i];
    return out;
}

static void _honda_unpack(uint64_t raw, HondaFrameData* f) {
    uint8_t key[8];
    for(int i = 7; i >= 0; i--) {
        key[i] = (uint8_t)(raw & 0xFFu);
        raw >>= 8;
    }

    f->type_b        = (key[0] >> 7) & 0x01u;
    f->type_b_header = (key[0] >> 4) & 0x07u;
    f->button        =  key[0]       & 0x0Fu;
    f->serial  = ((uint32_t)key[1] << 20) | ((uint32_t)key[2] << 12) |
                 ((uint32_t)key[3] << 4)  | ((uint32_t)(key[4] >> 4) & 0x0Fu);
    f->counter = ((uint32_t)key[5] << 16) | ((uint32_t)key[6] << 8) | (uint32_t)key[7];
    f->mode    = 0x2u;   /* default mode; will be set properly on decode */

    /* Recompute XOR checksum */
    uint8_t fb[8] = {0};
    if(!f->type_b) {
        fb[0] = (uint8_t)((f->button << 4) | ((f->serial >> 24) & 0x0Fu));
        fb[1] = (uint8_t)((f->serial >> 16) & 0xFFu);
        fb[2] = (uint8_t)((f->serial >> 8)  & 0xFFu);
        fb[3] = (uint8_t)( f->serial        & 0xFFu);
        fb[4] = (uint8_t)((f->counter >> 16) & 0xFFu);
        fb[5] = (uint8_t)((f->counter >> 8)  & 0xFFu);
        fb[6] = (uint8_t)( f->counter        & 0xFFu);
    } else {
        fb[0] = (uint8_t)((f->type_b_header << 4) | (f->button & 0x0Fu));
        fb[1] = (uint8_t)((f->serial >> 20) & 0xFFu);
        fb[2] = (uint8_t)((f->serial >> 12) & 0xFFu);
        fb[3] = (uint8_t)((f->serial >> 4)  & 0xFFu);
        fb[4] = (uint8_t)(((f->serial & 0x0Fu) << 4) | ((f->counter >> 20) & 0x0Fu));
        fb[5] = (uint8_t)((f->counter >> 12) & 0xFFu);
        fb[6] = (uint8_t)((f->counter >> 4)  & 0xFFu);
    }
    f->checksum = _honda_xor_checksum(fb);
}

/* ============================================================================
 * Decoder state
 * ==========================================================================*/
#define HONDA_HALF_BIT_BUF 512u

typedef enum {
    HondaDecoderStepReset = 0,
    HondaDecoderStepAccumulate,
} HondaDecoderStep;

typedef struct SubGhzProtocolDecoderHonda {
    SubGhzProtocolDecoderBase base;
    SubGhzBlockDecoder        decoder;
    SubGhzBlockGeneric        generic;

    uint8_t  half_bits[HONDA_HALF_BIT_BUF];
    uint16_t hb_count;
    uint16_t consecutive_clean;

    HondaFrameData frame;
    bool           frame_valid;
} SubGhzProtocolDecoderHonda;

/* ============================================================================
 * Encoder state
 * ==========================================================================*/
#define HONDA_ENC_BUF_SIZE 512u

typedef struct SubGhzProtocolEncoderHonda {
    SubGhzProtocolEncoderBase   base;
    SubGhzProtocolBlockEncoder  encoder;
    SubGhzBlockGeneric          generic;

    HondaFrameData frame;
    uint8_t        active_button;
} SubGhzProtocolEncoderHonda;

const SubGhzProtocolDecoder subghz_protocol_honda_decoder;
const SubGhzProtocolEncoder subghz_protocol_honda_encoder;
const SubGhzProtocol        subghz_protocol_honda;

/* ============================================================================
 * Duration classifier
 * Pandora uses TE_SHORT=250us, TE_LONG=480us from Brand_Auto_Honda_TX
 * ==========================================================================*/
static uint8_t _classify_duration(uint32_t abs_dur) {
    if(abs_dur >= (HONDA_TE_SHORT - HONDA_TE_DELTA) &&
       abs_dur <= (HONDA_TE_SHORT + HONDA_TE_DELTA)) return 1;
    if(abs_dur >= (HONDA_TE_LONG  - HONDA_TE_DELTA) &&
       abs_dur <= (HONDA_TE_LONG  + HONDA_TE_DELTA)) return 2;
    if(abs_dur >= (HONDA_TE_SHORT - HONDA_TE_DELTA - 30u) &&
       abs_dur <= (HONDA_TE_SHORT + HONDA_TE_DELTA + 30u)) return 1;
    if(abs_dur >= (HONDA_TE_LONG  - HONDA_TE_DELTA - 30u) &&
       abs_dur <= (HONDA_TE_LONG  + HONDA_TE_DELTA + 30u)) return 2;
    return 0;
}

/* ============================================================================
 * Manchester decoder
 * ==========================================================================*/
static bool _honda_try_decode_polarity(SubGhzProtocolDecoderHonda* inst, bool invert) {
    uint8_t* hb  = inst->half_bits;
    uint16_t cnt = inst->hb_count;

    int16_t  best_preamble_end = -1;
    uint16_t preamble_count    = 0;

    for(uint16_t i = 1; i < cnt; i++) {
        if(hb[i] != hb[i - 1]) {
            preamble_count++;
        } else {
            if(preamble_count >= HONDA_MIN_PREAMBLE_COUNT) {
                best_preamble_end = (int16_t)i;
                break;
            }
            preamble_count = 0;
        }
    }

    if(best_preamble_end < 0 && preamble_count >= HONDA_MIN_PREAMBLE_COUNT)
        return false; /* preamble only */
    if(best_preamble_end < 0)
        best_preamble_end = 0;

    /* Skip same-level at sync */
    uint16_t i = (uint16_t)best_preamble_end;
    while(i + 1 < cnt && hb[i] == hb[i + 1]) i++;

    /* Manchester decode */
    uint8_t decoded[16] = {0};
    uint8_t bit_count   = 0;

    while(i + 1 < cnt && bit_count < 128u) {
        uint8_t h0 = hb[i];
        uint8_t h1 = hb[i + 1];
        if(h0 != h1) {
            uint8_t bit_val;
            if(!invert)
                bit_val = (h0 == 1 && h1 == 0) ? 1u : 0u;
            else
                bit_val = (h0 == 0 && h1 == 1) ? 1u : 0u;
            uint8_t byte_idx = bit_count / 8u;
            uint8_t bit_idx  = 7u - (bit_count % 8u);
            if(bit_val)
                decoded[byte_idx] |= (uint8_t)(1u << bit_idx);
            else
                decoded[byte_idx] &= (uint8_t)(~(1u << bit_idx));
            bit_count++;
            i += 2;
        } else {
            i++;
        }
    }

    if(bit_count < HONDA_MIN_BITS) return false;

    FURI_LOG_D(
        TAG, "pol=%s bits=%u: %02X %02X %02X %02X %02X %02X %02X %02X",
        invert ? "INV" : "NOR", bit_count,
        decoded[0], decoded[1], decoded[2], decoded[3],
        decoded[4], decoded[5], decoded[6], decoded[7]);

    /* --- Type-A: [4b btn][28b serial][24b counter][8b csum] = 64 bits --- */
    if(bit_count >= 64u) {
        uint8_t  btn     = (uint8_t)_bits_get(decoded, 0, 4);
        uint32_t serial  = _bits_get(decoded, 4, 28);
        uint32_t counter = _bits_get(decoded, 32, 24);
        uint8_t  csum    = (uint8_t)_bits_get(decoded, 56, 8);

        uint8_t xor_check = 0;
        for(uint8_t b = 0; b < 7; b++) xor_check ^= decoded[b];

        if(xor_check == csum ||
           (btn <= HONDA_BTN_LOCK2PRESS && btn > 0 &&
            serial != 0 && serial != 0xFFFFFFFu &&
            __builtin_popcount(xor_check ^ csum) <= 4)) {
            inst->frame.type_b        = false;
            inst->frame.type_b_header = 0;
            inst->frame.button        = btn;
            inst->frame.serial        = serial;
            inst->frame.counter       = counter;
            inst->frame.checksum      = csum;
            inst->frame.mode          = 0x2u;
            inst->frame_valid         = true;
            FURI_LOG_I(
                TAG, "DECODED TypeA pol=%s btn=%u ser=%07lX cnt=%06lX",
                invert ? "INV" : "NOR",
                btn, (unsigned long)serial, (unsigned long)counter);
            return true;
        }
    }

    /* --- Type-B: [4b hdr][4b btn][28b serial][24b counter][8b csum] = 68 bits --- */
    if(bit_count >= 68u) {
        uint8_t  hdr     = (uint8_t)_bits_get(decoded, 0, 4);
        uint8_t  btn     = (uint8_t)_bits_get(decoded, 4, 4);
        uint32_t serial  = _bits_get(decoded, 8, 28);
        uint32_t counter = _bits_get(decoded, 36, 24);
        uint8_t  csum    = (uint8_t)_bits_get(decoded, 60, 8);

        uint8_t calc_csum_b = 0;
        {
            uint8_t fb[7] = {0};
            fb[0] = (uint8_t)((hdr << 4) | (btn & 0x0Fu));
            fb[1] = (uint8_t)((serial >> 20) & 0xFFu);
            fb[2] = (uint8_t)((serial >> 12) & 0xFFu);
            fb[3] = (uint8_t)((serial >> 4)  & 0xFFu);
            fb[4] = (uint8_t)(((serial & 0x0Fu) << 4) | ((counter >> 20) & 0x0Fu));
            fb[5] = (uint8_t)((counter >> 12) & 0xFFu);
            fb[6] = (uint8_t)((counter >> 4)  & 0xFFu);
            for(uint8_t _i = 0; _i < 7; _i++) calc_csum_b ^= fb[_i];
        }

        if(btn <= HONDA_BTN_LOCK2PRESS &&
           (calc_csum_b == csum || __builtin_popcount(calc_csum_b ^ csum) <= 1)) {
            inst->frame.type_b        = true;
            inst->frame.type_b_header = hdr;
            inst->frame.button        = btn;
            inst->frame.serial        = serial;
            inst->frame.counter       = counter;
            inst->frame.checksum      = csum;
            inst->frame.mode          = (uint8_t)((decoded[7] >> 4) & 0x0Fu);
            inst->frame_valid         = true;
            FURI_LOG_I(
                TAG, "DECODED TypeB pol=%s hdr=%u btn=%u ser=%07lX cnt=%06lX",
                invert ? "INV" : "NOR",
                hdr, btn, (unsigned long)serial, (unsigned long)counter);
            return true;
        }
    }

    return false;
}

static bool _honda_try_decode(SubGhzProtocolDecoderHonda* inst) {
    if(inst->hb_count < 40u) return false;
    if(_honda_try_decode_polarity(inst, true))  return true;
    if(_honda_try_decode_polarity(inst, false)) return true;
    return false;
}

/* ============================================================================
 * Encoder — build Manchester upload buffer
 * Uses Pandora timing: preamble 312 cycles × 250us, data bits 480/250us
 * ==========================================================================*/
static void _honda_build_upload(SubGhzProtocolEncoderHonda* inst) {
    LevelDuration* buf = inst->encoder.upload;
    size_t idx = 0;

    buf[idx++] = level_duration_make(false, HONDA_GUARD_TIME_US);

    for(uint16_t p = 0; p < (uint16_t)(HONDA_MIN_PREAMBLE_COUNT * 2u); p++) {
        buf[idx++] = level_duration_make((p & 1u) != 0u, HONDA_TE_SHORT);
    }

    uint8_t frame[9] = {0};
    uint8_t btn = inst->active_button & 0x0Fu;

    if(!inst->frame.type_b) {
        _bits_set(frame, 0,  4,  btn);
        _bits_set(frame, 4,  28, inst->frame.serial);
        _bits_set(frame, 32, 24, inst->frame.counter);
        _bits_set(frame, 56, 8,  _honda_xor_checksum(frame));
    } else {
        _bits_set(frame, 0,  4,  inst->frame.type_b_header);
        _bits_set(frame, 4,  4,  btn);
        _bits_set(frame, 8,  28, inst->frame.serial);
        _bits_set(frame, 36, 24, inst->frame.counter);

        uint8_t cs = 0;
        for(uint8_t i = 0; i < 7; i++) cs ^= frame[i];
        _bits_set(frame, 60, 8, cs);
    }

    uint8_t total_bits = inst->frame.type_b ?
        (uint8_t)HONDA_FRAME_BITS_B : (uint8_t)HONDA_FRAME_BITS;

    /* Manchester encode inverted: bit-1 = LOW/HIGH, bit-0 = HIGH/LOW, all at TE_SHORT */
    for(uint8_t b = 0; b < total_bits; b++) {
        uint8_t byte_idx = b / 8u;
        uint8_t bit_idx  = 7u - (b % 8u);
        uint8_t bit      = (frame[byte_idx] >> bit_idx) & 1u;
        if(bit) {
            /* bit 1: LOW then HIGH */
            buf[idx++] = level_duration_make(false, HONDA_TE_SHORT);
            buf[idx++] = level_duration_make(true,  HONDA_TE_SHORT);
        } else {
            /* bit 0: HIGH then LOW */
            buf[idx++] = level_duration_make(true,  HONDA_TE_SHORT);
            buf[idx++] = level_duration_make(false, HONDA_TE_SHORT);
        }
        furi_check(idx < HONDA_ENC_BUF_SIZE);
    }

    buf[idx++] = level_duration_make(false, HONDA_GUARD_TIME_US);

    inst->encoder.size_upload = idx;
    inst->encoder.front       = 0;
}

/* ============================================================================
 * Protocol tables
 * ==========================================================================*/
const SubGhzProtocolDecoder subghz_protocol_honda_decoder = {
    .alloc         = subghz_protocol_decoder_honda_alloc,
    .free          = subghz_protocol_decoder_honda_free,
    .feed          = subghz_protocol_decoder_honda_feed,
    .reset         = subghz_protocol_decoder_honda_reset,
    .get_hash_data = subghz_protocol_decoder_honda_get_hash_data,
    .serialize     = subghz_protocol_decoder_honda_serialize,
    .deserialize   = subghz_protocol_decoder_honda_deserialize,
    .get_string    = subghz_protocol_decoder_honda_get_string,
};

const SubGhzProtocolEncoder subghz_protocol_honda_encoder = {
    .alloc       = subghz_protocol_encoder_honda_alloc,
    .free        = subghz_protocol_encoder_honda_free,
    .deserialize = subghz_protocol_encoder_honda_deserialize,
    .stop        = subghz_protocol_encoder_honda_stop,
    .yield       = subghz_protocol_encoder_honda_yield,
};

const SubGhzProtocol subghz_protocol_honda = {
    .name    = SUBGHZ_PROTOCOL_HONDA_NAME,
    .type    = SubGhzProtocolTypeDynamic,
    .flag    = SubGhzProtocolFlag_433 | SubGhzProtocolFlag_315 |
               SubGhzProtocolFlag_AM  | SubGhzProtocolFlag_Decodable |
               SubGhzProtocolFlag_Load | SubGhzProtocolFlag_Save | SubGhzProtocolFlag_Send,
    .decoder = &subghz_protocol_honda_decoder,
    .encoder = &subghz_protocol_honda_encoder,
};

/* ============================================================================
 * Custom button helpers
 *   1 → Lock      (0x01)
 *   2 → Unlock    (0x02)
 *   3 → Trunk     (0x04)
 *   4 → Panic     (0x08)
 *   5 → RStart    (0x05)
 * ==========================================================================*/
uint8_t subghz_protocol_honda_btn_to_custom(uint8_t btn) {
    switch(btn) {
    case HONDA_BTN_LOCK:       return 1;
    case HONDA_BTN_UNLOCK:     return 2;
    case HONDA_BTN_TRUNK:      return 3;
    case HONDA_BTN_PANIC:      return 4;
    case HONDA_BTN_RSTART:     return 5;
    default:                   return 1;
    }
}

uint8_t subghz_protocol_honda_custom_to_btn(uint8_t custom) {
    switch(custom) {
    case 1: return HONDA_BTN_LOCK;
    case 2: return HONDA_BTN_UNLOCK;
    case 3: return HONDA_BTN_TRUNK;
    case 4: return HONDA_BTN_PANIC;
    case 5: return HONDA_BTN_RSTART;
    default: return HONDA_BTN_LOCK;
    }
}

/* ============================================================================
 * Decoder
 * ==========================================================================*/
void* subghz_protocol_decoder_honda_alloc(SubGhzEnvironment* environment) {
    UNUSED(environment);
    SubGhzProtocolDecoderHonda* inst = malloc(sizeof(SubGhzProtocolDecoderHonda));
    furi_check(inst);
    memset(inst, 0, sizeof(SubGhzProtocolDecoderHonda));
    inst->base.protocol     = &subghz_protocol_honda;
    inst->generic.protocol_name = inst->base.protocol->name;
    inst->frame_valid       = false;
    FURI_LOG_I(TAG, "decoder allocated");
    return inst;
}

void subghz_protocol_decoder_honda_free(void* context) {
    furi_assert(context);
    free(context);
}

void subghz_protocol_decoder_honda_reset(void* context) {
    furi_assert(context);
    SubGhzProtocolDecoderHonda* inst = context;
    inst->decoder.parser_step   = HondaDecoderStepReset;
    inst->decoder.te_last       = 0;
    inst->hb_count              = 0;
    inst->consecutive_clean     = 0;
    /* DO NOT clear frame/frame_valid — get_string needs them after reset */
}

void subghz_protocol_decoder_honda_feed(void* context, bool level, uint32_t duration) {
    furi_assert(context);
    SubGhzProtocolDecoderHonda* inst = context;
    uint8_t lvl       = level ? 1u : 0u;
    uint8_t dur_class = _classify_duration(duration);

    if(dur_class > 0) {
        inst->consecutive_clean++;
        if(dur_class == 1) {
            if(inst->hb_count < HONDA_HALF_BIT_BUF)
                inst->half_bits[inst->hb_count++] = lvl;
        } else {
            if(inst->hb_count + 2u <= HONDA_HALF_BIT_BUF) {
                inst->half_bits[inst->hb_count++] = lvl;
                inst->half_bits[inst->hb_count++] = lvl;
            }
        }
    } else {
        if(inst->hb_count >= (HONDA_MIN_PREAMBLE_COUNT + 16u)) {
            if(_honda_try_decode(inst)) {
                inst->generic.data = _honda_pack(&inst->frame);
                inst->generic.data_count_bit = inst->frame.type_b ?
                    (uint8_t)HONDA_FRAME_BITS_B : (uint8_t)HONDA_FRAME_BITS;
                inst->generic.serial = inst->frame.serial;
                inst->generic.btn    = inst->frame.button;
                inst->generic.cnt    = inst->frame.counter;
                FURI_LOG_I(
                    TAG, "FRAME btn=%u ser=%07lX cnt=%06lX",
                    inst->frame.button,
                    (unsigned long)inst->frame.serial,
                    (unsigned long)inst->frame.counter);

                uint8_t custom = subghz_protocol_honda_btn_to_custom(inst->frame.button);
                if(subghz_custom_btn_get_original() == 0)
                    subghz_custom_btn_set_original(custom);
                subghz_custom_btn_set_max(HONDA_CUSTOM_BTN_MAX);

                if(inst->base.callback)
                    inst->base.callback(&inst->base, inst->base.context);
            }
        }
        inst->hb_count          = 0;
        inst->consecutive_clean = 0;
    }
    inst->decoder.te_last = duration;
}

uint8_t subghz_protocol_decoder_honda_get_hash_data(void* context) {
    furi_assert(context);
    SubGhzProtocolDecoderHonda* inst = context;
    return (uint8_t)(inst->generic.data        ^
                    (inst->generic.data >> 8)   ^
                    (inst->generic.data >> 16)  ^
                    (inst->generic.data >> 24)  ^
                    (inst->generic.data >> 32));
}

SubGhzProtocolStatus subghz_protocol_decoder_honda_serialize(
    void* context, FlipperFormat* flipper_format, SubGhzRadioPreset* preset) {
    furi_assert(context);
    SubGhzProtocolDecoderHonda* inst = context;
    return subghz_block_generic_serialize(&inst->generic, flipper_format, preset);
}

SubGhzProtocolStatus subghz_protocol_decoder_honda_deserialize(
    void* context, FlipperFormat* flipper_format) {
    furi_assert(context);
    SubGhzProtocolDecoderHonda* inst = context;
    SubGhzProtocolStatus ret = subghz_block_generic_deserialize_check_count_bit(
        &inst->generic, flipper_format,
        subghz_protocol_honda_const.min_count_bit_for_found);
    if(ret == SubGhzProtocolStatusOk) {
        _honda_unpack(inst->generic.data, &inst->frame);
        inst->frame_valid      = true;
        inst->generic.serial   = inst->frame.serial;
        inst->generic.btn      = inst->frame.button;
        inst->generic.cnt      = inst->frame.counter;

        uint8_t custom = subghz_protocol_honda_btn_to_custom(inst->frame.button);
        if(subghz_custom_btn_get_original() == 0)
            subghz_custom_btn_set_original(custom);
        subghz_custom_btn_set_max(HONDA_CUSTOM_BTN_MAX);

        FURI_LOG_I(
            TAG, "deserialize: btn=%u ser=%07lX cnt=%06lX",
            inst->frame.button,
            (unsigned long)inst->frame.serial,
            (unsigned long)inst->frame.counter);
    }
    return ret;
}

void subghz_protocol_decoder_honda_get_string(void* context, FuriString* output) {
    furi_assert(context);
    SubGhzProtocolDecoderHonda* inst = context;

    if(!inst->frame_valid && inst->generic.data != 0) {
        _honda_unpack(inst->generic.data, &inst->frame);
        inst->frame_valid = true;
    }

    const char* btn_name;
    switch(inst->frame.button) {
    case HONDA_BTN_LOCK:       btn_name = "Lock";         break;
    case HONDA_BTN_UNLOCK:     btn_name = "Unlock";       break;
    case HONDA_BTN_TRUNK:      btn_name = "Trunk/Hatch";  break;
    case HONDA_BTN_PANIC:      btn_name = "Panic";        break;
    case HONDA_BTN_RSTART:     btn_name = "Remote Start"; break;
    case HONDA_BTN_LOCK2PRESS: btn_name = "Lock x2";      break;
    default:                   btn_name = "Unknown";      break;
    }

    furi_string_cat_printf(
        output,
        "%s %s %ubit\r\n"
        "Btn:%s (0x%X)\r\n"
        "Ser:%07lX\r\n"
        "Cnt:%06lX Chk:%02X Mode:%X\r\n",
        inst->generic.protocol_name,
        inst->frame.type_b ? "TB" : "TA",
        inst->generic.data_count_bit,
        btn_name,
        inst->frame.button,
        (unsigned long)inst->frame.serial,
        (unsigned long)inst->frame.counter,
        inst->frame.checksum,
        inst->frame.mode);
}

/* ============================================================================
 * Encoder
 * ==========================================================================*/
void* subghz_protocol_encoder_honda_alloc(SubGhzEnvironment* environment) {
    UNUSED(environment);
    SubGhzProtocolEncoderHonda* inst = malloc(sizeof(SubGhzProtocolEncoderHonda));
    furi_check(inst);
    memset(inst, 0, sizeof(SubGhzProtocolEncoderHonda));
    inst->base.protocol         = &subghz_protocol_honda;
    inst->generic.protocol_name = inst->base.protocol->name;
    inst->encoder.repeat        = 3;
    inst->encoder.size_upload   = 0;
    inst->encoder.upload        = malloc(HONDA_ENC_BUF_SIZE * sizeof(LevelDuration));
    furi_check(inst->encoder.upload);
    inst->encoder.is_running = false;
    inst->encoder.front      = 0;
    return inst;
}

void subghz_protocol_encoder_honda_free(void* context) {
    furi_assert(context);
    SubGhzProtocolEncoderHonda* inst = context;
    free(inst->encoder.upload);
    free(inst);
}

void subghz_protocol_encoder_honda_stop(void* context) {
    furi_assert(context);
    SubGhzProtocolEncoderHonda* inst = context;
    inst->encoder.is_running = false;
}

LevelDuration subghz_protocol_encoder_honda_yield(void* context) {
    furi_assert(context);
    SubGhzProtocolEncoderHonda* inst = context;
    if(inst->encoder.repeat == 0 || !inst->encoder.is_running) {
        inst->encoder.is_running = false;
        return level_duration_reset();
    }
    LevelDuration ret = inst->encoder.upload[inst->encoder.front];
    if(++inst->encoder.front >= inst->encoder.size_upload) {
        inst->encoder.repeat--;
        inst->encoder.front = 0;
    }
    return ret;
}

SubGhzProtocolStatus subghz_protocol_encoder_honda_deserialize(
    void* context, FlipperFormat* flipper_format) {
    furi_assert(context);
    SubGhzProtocolEncoderHonda* inst = context;
    SubGhzProtocolStatus ret = subghz_block_generic_deserialize(&inst->generic, flipper_format);
    if(ret != SubGhzProtocolStatusOk) return ret;

    _honda_unpack(inst->generic.data, &inst->frame);

    uint8_t custom = subghz_protocol_honda_btn_to_custom(inst->frame.button);
    if(subghz_custom_btn_get_original() == 0)
        subghz_custom_btn_set_original(custom);
    subghz_custom_btn_set_max(HONDA_CUSTOM_BTN_MAX);

    uint8_t active_custom = subghz_custom_btn_get();
    inst->active_button = (active_custom == SUBGHZ_CUSTOM_BTN_OK)
        ? subghz_protocol_honda_custom_to_btn(subghz_custom_btn_get_original())
        : subghz_protocol_honda_custom_to_btn(active_custom);

    inst->frame.counter = (inst->frame.counter +
        furi_hal_subghz_get_rolling_counter_mult()) & 0x00FFFFFFu;
    _honda_counter_increment(&inst->frame);

    inst->frame.button = inst->active_button;

    inst->generic.data = _honda_pack(&inst->frame);
    inst->generic.cnt  = inst->frame.counter;
    inst->generic.btn  = inst->active_button;

    flipper_format_rewind(flipper_format);
    uint8_t key_data[8];
    for(int i = 0; i < 8; i++)
        key_data[i] = (uint8_t)(inst->generic.data >> (56 - i * 8));
    flipper_format_update_hex(flipper_format, "Key", key_data, 8);

    _honda_build_upload(inst);
    inst->encoder.is_running = true;
    return SubGhzProtocolStatusOk;
}

void subghz_protocol_encoder_honda_set_button(void* context, uint8_t btn) {
    furi_assert(context);
    SubGhzProtocolEncoderHonda* inst = context;
    inst->active_button      = btn & 0x0Fu;
    inst->encoder.is_running = false;
    _honda_counter_increment(&inst->frame);
    inst->generic.data    = _honda_pack(&inst->frame);
    inst->generic.cnt     = inst->frame.counter;
    _honda_build_upload(inst);
    inst->encoder.repeat     = 3;
    inst->encoder.is_running = true;
}
