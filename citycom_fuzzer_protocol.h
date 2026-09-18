#pragma once

#include <stddef.h>
#include <stdint.h>

#define CITYCOM_FUZZER_UID_LENGTH 4U

/** Calculate the ISO 14443-A BCC for a UID. */
uint8_t citycom_fuzzer_calc_bcc(const uint8_t* uid, size_t uid_len);
