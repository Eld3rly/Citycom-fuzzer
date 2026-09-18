#include "citycom_fuzzer_protocol.h"

uint8_t citycom_fuzzer_calc_bcc(const uint8_t* uid, size_t uid_len) {
    if(!uid) {
        return 0;
    }

    uint8_t bcc = 0;
    for(size_t i = 0; i < uid_len; i++) {
        bcc ^= uid[i];
    }
    return bcc;
}
