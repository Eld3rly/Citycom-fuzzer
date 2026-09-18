#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <furi.h>
#include <furi/core/message_queue.h>
#include <furi_hal_nfc.h>
#include <furi_hal_random.h>
#include <gui/elements.h>
#include <gui/gui.h>
#include <gui/view_port.h>
#include <input/input.h>
#include <nfc/helpers/nfc_data_generator.h>
#include <nfc/nfc.h>
#include <nfc/nfc_device.h>
#include <nfc/nfc_listener.h>
#include <notification/notification_messages.h>
#include <lib/nfc/protocols/mf_classic/mf_classic.h>

#include "citycom_fuzzer_protocol.h"

#define CITYCOM_FUZZER_TAG                    "CitycomFuzzer"
#define CITYCOM_FUZZER_INPUT_QUEUE_LENGTH     8U
#define CITYCOM_FUZZER_SCREEN_WIDTH           128U
#define CITYCOM_FUZZER_AUTO_UID_INTERVAL_MS   100U
#define CITYCOM_FUZZER_BLOCK_0                0U
#define CITYCOM_FUZZER_BLOCK_4                4U
#define CITYCOM_FUZZER_BLOCK_0_PAYLOAD_OFFSET (CITYCOM_FUZZER_UID_LENGTH + 1U)
#define CITYCOM_FUZZER_ATQA_LENGTH            2U
#define CITYCOM_FUZZER_STATUS_LENGTH          32U
#define CITYCOM_FUZZER_DEFAULT_KEY            0xFFFFFFFFFFFFULL

static const uint8_t
    citycom_fuzzer_block0_tail[MF_CLASSIC_BLOCK_SIZE - CITYCOM_FUZZER_BLOCK_0_PAYLOAD_OFFSET] =
        {0x08, 0x04, 0x00, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69};

static const uint8_t citycom_fuzzer_block4[MF_CLASSIC_BLOCK_SIZE] = {
    0x4C,
    0x54,
    0x44,
    0x20,
    0x43,
    0x69,
    0x74,
    0x79,
    0x43,
    0x6F,
    0x6D,
    0x32,
    0x30,
    0x31,
    0x37,
    0x13,
};

static const uint8_t citycom_fuzzer_sector_trailer[MF_CLASSIC_BLOCK_SIZE] = {
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0x07,
    0x80,
    0x69,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
};

typedef enum {
    CitycomFuzzerStateReady,
    CitycomFuzzerStateStarting,
    CitycomFuzzerStateEmulating,
    CitycomFuzzerStateError,
} CitycomFuzzerState;

typedef struct {
    Gui* gui;
    ViewPort* view_port;
    FuriMessageQueue* input_queue;
    NotificationApp* notifications;

    Nfc* nfc;
    MfClassicData* card_data;
    NfcListener* listener;
    bool listener_running;

    bool running;
    bool startup_attempted;
    bool view_port_attached;
    bool auto_mode;

    CitycomFuzzerState state;
    char status[CITYCOM_FUZZER_STATUS_LENGTH];
    uint8_t uid[CITYCOM_FUZZER_UID_LENGTH];
    uint8_t bcc;
    uint8_t atqa[2];
    uint8_t sak;
} CitycomFuzzerApp;

static void citycom_fuzzer_free(CitycomFuzzerApp* app);
static void citycom_fuzzer_stop_listener(CitycomFuzzerApp* app, bool notify);

static void
    citycom_fuzzer_set_status(CitycomFuzzerApp* app, CitycomFuzzerState state, const char* status) {
    app->state = state;
    snprintf(app->status, sizeof(app->status), "%s", status);
}

static void citycom_fuzzer_redraw(CitycomFuzzerApp* app) {
    view_port_update(app->view_port);
}

static void citycom_fuzzer_setup_card(MfClassicData* mf) {
    memcpy(
        mf->block[CITYCOM_FUZZER_BLOCK_0].data + CITYCOM_FUZZER_BLOCK_0_PAYLOAD_OFFSET,
        citycom_fuzzer_block0_tail,
        sizeof(citycom_fuzzer_block0_tail));
    memcpy(
        mf->block[CITYCOM_FUZZER_BLOCK_4].data,
        citycom_fuzzer_block4,
        sizeof(citycom_fuzzer_block4));

    const uint8_t sector_count = mf_classic_get_total_sectors_num(mf->type);
    for(uint8_t sector = 0; sector < sector_count; sector++) {
        const uint8_t trailer = mf_classic_get_sector_trailer_num_by_sector(sector);
        memcpy(mf->block[trailer].data, citycom_fuzzer_sector_trailer, MF_CLASSIC_BLOCK_SIZE);
        mf_classic_set_key_found(mf, sector, MfClassicKeyTypeA, CITYCOM_FUZZER_DEFAULT_KEY);
        mf_classic_set_key_found(mf, sector, MfClassicKeyTypeB, CITYCOM_FUZZER_DEFAULT_KEY);
    }

    mf_classic_set_block_read(mf, CITYCOM_FUZZER_BLOCK_0, &mf->block[CITYCOM_FUZZER_BLOCK_0]);
    mf_classic_set_block_read(mf, CITYCOM_FUZZER_BLOCK_4, &mf->block[CITYCOM_FUZZER_BLOCK_4]);
}

static bool citycom_fuzzer_read_card_info(CitycomFuzzerApp* app) {
    MfClassicData* mf = app->card_data;
    if(!mf || !mf->iso14443_3a_data) {
        return false;
    }

    size_t uid_len = 0;
    const uint8_t* uid = mf_classic_get_uid(mf, &uid_len);
    if(!uid || uid_len != CITYCOM_FUZZER_UID_LENGTH) {
        return false;
    }

    memcpy(app->uid, uid, CITYCOM_FUZZER_UID_LENGTH);
    app->bcc = citycom_fuzzer_calc_bcc(app->uid, CITYCOM_FUZZER_UID_LENGTH);
    memcpy(app->atqa, mf->iso14443_3a_data->atqa, CITYCOM_FUZZER_ATQA_LENGTH);
    app->sak = mf->iso14443_3a_data->sak;
    return true;
}

static void citycom_fuzzer_randomize_uid(CitycomFuzzerApp* app) {
    for(size_t i = 0; i < CITYCOM_FUZZER_UID_LENGTH; i++) {
        app->uid[i] = (uint8_t)(furi_hal_random_get() & UINT8_MAX);
    }
    app->bcc = citycom_fuzzer_calc_bcc(app->uid, CITYCOM_FUZZER_UID_LENGTH);
}

static bool citycom_fuzzer_set_card_uid(MfClassicData* mf, const uint8_t* uid) {
    if(!mf || !uid) {
        return false;
    }

    if(!mf_classic_set_uid(mf, uid, CITYCOM_FUZZER_UID_LENGTH)) {
        return false;
    }

    memcpy(
        mf->block[CITYCOM_FUZZER_BLOCK_0].data + CITYCOM_FUZZER_BLOCK_0_PAYLOAD_OFFSET,
        citycom_fuzzer_block0_tail,
        sizeof(citycom_fuzzer_block0_tail));
    return true;
}

static bool citycom_fuzzer_update_card_uid(CitycomFuzzerApp* app) {
    if(!citycom_fuzzer_set_card_uid(app->card_data, app->uid)) {
        return false;
    }
    return citycom_fuzzer_read_card_info(app);
}

static void citycom_fuzzer_release_nfc(CitycomFuzzerApp* app) {
    if(app->card_data) {
        mf_classic_free(app->card_data);
        app->card_data = NULL;
    }
    if(app->nfc) {
        nfc_free(app->nfc);
        app->nfc = NULL;
    }
}

static bool citycom_fuzzer_nfc_init(CitycomFuzzerApp* app) {
    if(app->nfc && app->card_data) {
        return true;
    }

    if(app->nfc || app->card_data) {
        citycom_fuzzer_release_nfc(app);
    }

    if(furi_hal_nfc_is_hal_ready() != FuriHalNfcErrorNone) {
        FURI_LOG_E(CITYCOM_FUZZER_TAG, "NFC HAL not ready");
        citycom_fuzzer_set_status(app, CitycomFuzzerStateError, "NFC hardware error");
        return false;
    }

    app->nfc = nfc_alloc();
    app->card_data = mf_classic_alloc();
    NfcDevice* generated_device = nfc_device_alloc();
    if(!app->nfc || !app->card_data || !generated_device) {
        FURI_LOG_E(CITYCOM_FUZZER_TAG, "NFC init failed");
        if(generated_device) {
            nfc_device_free(generated_device);
        }
        citycom_fuzzer_release_nfc(app);
        citycom_fuzzer_set_status(app, CitycomFuzzerStateError, "NFC init failed");
        return false;
    }

    nfc_data_generator_fill_data(NfcDataGeneratorTypeMfClassic1k_4b, generated_device);
    if(nfc_device_get_protocol(generated_device) != NfcProtocolMfClassic) {
        FURI_LOG_E(CITYCOM_FUZZER_TAG, "Mifare Classic data missing");
        nfc_device_free(generated_device);
        citycom_fuzzer_release_nfc(app);
        citycom_fuzzer_set_status(app, CitycomFuzzerStateError, "Card data missing");
        return false;
    }

    nfc_device_copy_data(generated_device, NfcProtocolMfClassic, app->card_data);
    nfc_device_free(generated_device);
    citycom_fuzzer_setup_card(app->card_data);
    return true;
}

static NfcCommand citycom_fuzzer_listener_callback(NfcGenericEvent event, void* context) {
    UNUSED(event);
    UNUSED(context);
    return NfcCommandContinue;
}

static bool citycom_fuzzer_start_listener(CitycomFuzzerApp* app) {
    if(app->listener_running) {
        return true;
    }
    if(!citycom_fuzzer_nfc_init(app)) {
        return false;
    }

    if(!app->card_data) {
        citycom_fuzzer_set_status(app, CitycomFuzzerStateError, "Card data missing");
        return false;
    }

    app->listener = nfc_listener_alloc(app->nfc, NfcProtocolMfClassic, app->card_data);
    if(!app->listener) {
        FURI_LOG_E(CITYCOM_FUZZER_TAG, "Listener allocation failed");
        citycom_fuzzer_set_status(app, CitycomFuzzerStateError, "Listener allocation failed");
        return false;
    }

    nfc_listener_start(app->listener, citycom_fuzzer_listener_callback, app);
    /* Let the NFC worker reach Running before the app can stop it. */
    furi_thread_yield();
    app->listener_running = true;

    notification_message(app->notifications, &sequence_blink_start_cyan);
    citycom_fuzzer_set_status(app, CitycomFuzzerStateEmulating, "NFC emulation ON");
    return true;
}

static void citycom_fuzzer_stop_listener(CitycomFuzzerApp* app, bool notify) {
    if(!app->listener) {
        return;
    }

    if(app->listener_running) {
        nfc_listener_stop(app->listener);
        app->listener_running = false;
        if(notify && app->notifications) {
            notification_message(app->notifications, &sequence_blink_stop);
        }
    }

    nfc_listener_free(app->listener);
    app->listener = NULL;
}

static const char* citycom_fuzzer_mode_status(const CitycomFuzzerApp* app) {
    return app->auto_mode ? "Auto mode / 100 ms" : "NFC emulation ON";
}

static void citycom_fuzzer_update_mode_status(CitycomFuzzerApp* app) {
    if(app->state == CitycomFuzzerStateError) {
        return;
    }

    const CitycomFuzzerState state = app->listener_running ? CitycomFuzzerStateEmulating :
                                                             CitycomFuzzerStateReady;
    citycom_fuzzer_set_status(app, state, citycom_fuzzer_mode_status(app));
}

static bool citycom_fuzzer_apply_random_uid(CitycomFuzzerApp* app) {
    citycom_fuzzer_randomize_uid(app);

    if(!citycom_fuzzer_nfc_init(app)) {
        return false;
    }

    if(!citycom_fuzzer_update_card_uid(app)) {
        FURI_LOG_E(CITYCOM_FUZZER_TAG, "UID setup failed");
        citycom_fuzzer_set_status(app, CitycomFuzzerStateError, "UID setup failed");
        return false;
    }

    /* The listener owns a snapshot of card_data, so replace it after updates. */
    if(app->listener_running) {
        citycom_fuzzer_stop_listener(app, false);
    }

    if(!citycom_fuzzer_start_listener(app)) {
        return false;
    }

    citycom_fuzzer_set_status(app, CitycomFuzzerStateEmulating, citycom_fuzzer_mode_status(app));
    return true;
}

static const char* citycom_fuzzer_mode_label(const CitycomFuzzerApp* app) {
    return app->auto_mode ? "^Stop" : "^Auto";
}

static const char* citycom_fuzzer_rf_label(const CitycomFuzzerApp* app) {
    if(app->auto_mode) {
        return "AUTO";
    }

    switch(app->state) {
    case CitycomFuzzerStateEmulating:
        return "RF";
    case CitycomFuzzerStateStarting:
        return "...";
    case CitycomFuzzerStateError:
        return "ERR";
    case CitycomFuzzerStateReady:
    default:
        return "--";
    }
}

static void citycom_fuzzer_draw_top_bar(Canvas* canvas, const CitycomFuzzerApp* app) {
    canvas_set_color(canvas, ColorBlack);
    canvas_draw_box(canvas, 0, 0, CITYCOM_FUZZER_SCREEN_WIDTH, 14);

    canvas_set_color(canvas, ColorWhite);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 3, 12, "CityCom");

    canvas_draw_rframe(canvas, 88, 2, 38, 10, 2);
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str_aligned(
        canvas, 107, 10, AlignCenter, AlignBottom, citycom_fuzzer_mode_label(app));

    canvas_set_color(canvas, ColorBlack);
}

static void citycom_fuzzer_draw_callback(Canvas* canvas, void* context) {
    CitycomFuzzerApp* app = context;
    if(!app) {
        return;
    }

    canvas_clear(canvas);
    canvas_set_color(canvas, ColorBlack);
    citycom_fuzzer_draw_top_bar(canvas, app);

    char uid_line[32];
    snprintf(
        uid_line,
        sizeof(uid_line),
        "%02X %02X %02X %02X",
        app->uid[0],
        app->uid[1],
        app->uid[2],
        app->uid[3]);

    char meta_line[32];
    snprintf(
        meta_line,
        sizeof(meta_line),
        "%s  B:%02X A:%02X%02X S:%02X",
        citycom_fuzzer_rf_label(app),
        app->bcc,
        app->atqa[0],
        app->atqa[1],
        app->sak);

    canvas_draw_frame(canvas, 2, 17, 124, 21);
    canvas_draw_box(canvas, 4, 19, 22, 17);
    canvas_set_color(canvas, ColorWhite);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 7, 32, "ID");

    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str_aligned(canvas, 77, 33, AlignCenter, AlignBottom, uid_line);

    canvas_set_font(canvas, FontSecondary);
    canvas_draw_line(canvas, 2, 42, 126, 42);
    canvas_draw_str_aligned(canvas, 64, 51, AlignCenter, AlignBottom, meta_line);
    canvas_draw_str(canvas, 3, 61, app->status);

    if(!app->auto_mode) {
        elements_button_right(canvas, "New");
    }
}

static void citycom_fuzzer_input_port_callback(InputEvent* event, void* context) {
    CitycomFuzzerApp* app = context;
    if(!app || !app->input_queue) {
        return;
    }

    const FuriStatus status = furi_message_queue_put(app->input_queue, event, FuriWaitForever);
    if(status != FuriStatusOk) {
        FURI_LOG_W(CITYCOM_FUZZER_TAG, "Input event dropped");
    }
}

static void citycom_fuzzer_handle_input(CitycomFuzzerApp* app, const InputEvent* event) {
    if(event->type == InputTypeShort && event->key == InputKeyBack) {
        app->running = false;
        return;
    }

    if(event->type == InputTypeShort && event->key == InputKeyUp) {
        app->auto_mode = !app->auto_mode;
        citycom_fuzzer_update_mode_status(app);
        citycom_fuzzer_redraw(app);
        return;
    }

    if(event->type == InputTypeShort && event->key == InputKeyRight && !app->auto_mode) {
        citycom_fuzzer_apply_random_uid(app);
        citycom_fuzzer_redraw(app);
    }
}

static CitycomFuzzerApp* citycom_fuzzer_alloc(void) {
    CitycomFuzzerApp* app = malloc(sizeof(*app));
    if(!app) {
        return NULL;
    }

    memset(app, 0, sizeof(*app));
    app->gui = furi_record_open(RECORD_GUI);
    app->notifications = furi_record_open(RECORD_NOTIFICATION);
    app->input_queue =
        furi_message_queue_alloc(CITYCOM_FUZZER_INPUT_QUEUE_LENGTH, sizeof(InputEvent));
    app->view_port = view_port_alloc();

    if(!app->gui || !app->notifications || !app->input_queue || !app->view_port) {
        citycom_fuzzer_free(app);
        return NULL;
    }

    view_port_draw_callback_set(app->view_port, citycom_fuzzer_draw_callback, app);
    view_port_input_callback_set(app->view_port, citycom_fuzzer_input_port_callback, app);

    app->state = CitycomFuzzerStateStarting;
    snprintf(app->status, sizeof(app->status), "Starting...");
    citycom_fuzzer_randomize_uid(app);
    return app;
}

static void citycom_fuzzer_free(CitycomFuzzerApp* app) {
    if(!app) {
        return;
    }

    citycom_fuzzer_stop_listener(app, true);
    citycom_fuzzer_release_nfc(app);

    if(app->gui && app->view_port && app->view_port_attached) {
        gui_remove_view_port(app->gui, app->view_port);
    }
    if(app->view_port) {
        view_port_free(app->view_port);
        app->view_port = NULL;
    }

    if(app->input_queue) {
        furi_message_queue_free(app->input_queue);
        app->input_queue = NULL;
    }

    if(app->notifications) {
        furi_record_close(RECORD_NOTIFICATION);
    }
    if(app->gui) {
        furi_record_close(RECORD_GUI);
    }
    free(app);
}

int32_t citycom_fuzzer_app(void* p) {
    UNUSED(p);

    CitycomFuzzerApp* app = citycom_fuzzer_alloc();
    if(!app) {
        return -1;
    }

    gui_add_view_port(app->gui, app->view_port, GuiLayerFullscreen);
    app->view_port_attached = true;
    citycom_fuzzer_set_status(app, CitycomFuzzerStateReady, "Press Right / wait");
    citycom_fuzzer_redraw(app);

    app->running = true;
    while(app->running) {
        InputEvent event;
        const FuriStatus status =
            furi_message_queue_get(app->input_queue, &event, CITYCOM_FUZZER_AUTO_UID_INTERVAL_MS);
        if(status == FuriStatusOk) {
            citycom_fuzzer_handle_input(app, &event);
            continue;
        }
        if(status != FuriStatusErrorTimeout) {
            FURI_LOG_W(CITYCOM_FUZZER_TAG, "Input queue error");
            continue;
        }

        if(!app->startup_attempted) {
            app->startup_attempted = true;
            citycom_fuzzer_set_status(app, CitycomFuzzerStateStarting, "Starting NFC...");
            citycom_fuzzer_redraw(app);
            citycom_fuzzer_apply_random_uid(app);
            citycom_fuzzer_redraw(app);
            continue;
        }

        if(app->auto_mode) {
            citycom_fuzzer_apply_random_uid(app);
            citycom_fuzzer_redraw(app);
        }
    }

    citycom_fuzzer_free(app);
    return 0;
}
