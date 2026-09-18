#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include "citycom_fuzzer_protocol.h"

int main(void) {
    static const uint8_t citycom_uid[CITYCOM_FUZZER_UID_LENGTH] = {0x44, 0xA4, 0x7B, 0xAC};
    static const uint8_t zero_uid[CITYCOM_FUZZER_UID_LENGTH] = {0};
    static const uint8_t cancelling_uid[CITYCOM_FUZZER_UID_LENGTH] = {0xFF, 0x00, 0xFF, 0x00};

    assert(citycom_fuzzer_calc_bcc(citycom_uid, sizeof(citycom_uid)) == 0x37);
    assert(citycom_fuzzer_calc_bcc(zero_uid, sizeof(zero_uid)) == 0x00);
    assert(citycom_fuzzer_calc_bcc(cancelling_uid, sizeof(cancelling_uid)) == 0x00);
    assert(citycom_fuzzer_calc_bcc(NULL, 0) == 0x00);

    return 0;
}
