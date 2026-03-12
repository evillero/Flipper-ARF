#pragma once

#include "subghz_txrx.h"

struct SubGhzTxRx {
    SubGhzWorker* worker;

    SubGhzEnvironment* environment;
    SubGhzReceiver* receiver;
    SubGhzTransmitter* transmitter;
    SubGhzProtocolDecoderBase* decoder_result;
    FlipperFormat* fff_data;

    SubGhzRadioPreset* preset;
    SubGhzSetting* setting;

    uint8_t hopper_timeout;
    uint8_t hopper_idx_frequency;
    bool is_database_loaded;
    SubGhzHopperState hopper_state;

    uint8_t mod_hopper_idx;            // index into setting presets (wraps around)
    uint8_t mod_hopper_timer;          // countdown ticks before advancing modulation
    uint8_t mod_hopper_dwell;          // stored dwell ticks (configurable)
    float mod_hopper_rssi_threshold;   // RSSI threshold; NAN = no RSSI gating
    bool mod_hopper_running;           // is mod hopping active

    SubGhzTxRxState txrx_state;
    SubGhzSpeakerState speaker_state;
    const SubGhzDevice* radio_device;
    SubGhzRadioDeviceType radio_device_type;

    SubGhzTxRxNeedSaveCallback need_save_callback;
    void* need_save_context;

    bool debug_pin_state;
};
