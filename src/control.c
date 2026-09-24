// MIT License
//
// Copyright (c) 2026 Kevin Thomas
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
// Author:  Kevin Thomas
// Email:   kevin@mytechnotalent.com
// GitHub:  https://github.com/mytechnotalent/hvac-automation-node
// File:    control.c
// Desc:    Implements the sealed SETPOINT command path that opens,
//          authorizes, and applies remote BMS commands with a guarded
//          command set and a bounded setpoint band.
// Created: 2026

#include "control.h"
#include "hvac_auth.h"
#include "envelope.h"
#include "hvac.h"
#include "crypto_aead.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/**
 * @brief Derived field key used to open sealed command envelopes.
 */
static uint8_t g_control_key[CRYPTO_AEAD_KEY_LEN];

/**
 * @brief True once the field key has been installed.
 */
static bool g_control_key_ready;

/**
 * @brief Anti-replay authorization record for remote commands.
 */
static hvac_auth_t g_control_auth;

/**
 * @brief Setpoint recovered from the last accepted remote command.
 */
static int16_t g_control_setpoint;

/**
 * @brief Read one 32-bit little-endian value.
 *
 * @param p Pointer to four little-endian bytes.
 * @return uint32_t Decoded value.
 */
static uint32_t control_get_u32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8u) |
           ((uint32_t)p[2] << 16u) | ((uint32_t)p[3] << 24u);
}

/**
 * @brief Read one 16-bit little-endian signed setpoint.
 *
 * @param p Pointer to two little-endian bytes.
 * @return int16_t Decoded setpoint in tenths of a degree Celsius.
 */
static int16_t control_get_i16(const uint8_t *p) {
    return (int16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8u));
}

/**
 * @brief Report whether a decoded setpoint is inside the safe band.
 *
 * @param setpoint Setpoint in tenths of a degree Celsius.
 * @return bool true when the setpoint is inside the provisioning band.
 */
static bool control_setpoint_ok(int16_t setpoint) {
    return (setpoint >= HVAC_SETPOINT_MIN_TENTHS) &&
           (setpoint <= HVAC_SETPOINT_MAX_TENTHS);
}

/**
 * @brief Range check a recovered command body and its pointers.
 *
 * The command byte is checked against the guarded SETPOINT set so no raw
 * value can reach the actuator decision.
 *
 * @param pt Pointer to the recovered command plaintext.
 * @param len Number of recovered plaintext bytes.
 * @param seq Pointer to store the sequence number.
 * @param tag Pointer to the tag output buffer.
 * @param setpoint Pointer to store the decoded setpoint.
 * @return bool true when the body is well formed and in the guarded set.
 */
static bool control_args_ok(const uint8_t *pt, size_t len, uint32_t *seq,
                            uint8_t *tag, int16_t *setpoint) {
    return (pt != NULL) && (seq != NULL) && (tag != NULL) &&
           (setpoint != NULL) && (len >= CONTROL_COMMAND_LEN) &&
           (pt[4] == HVAC_COMMAND_SETPOINT);
}

/**
 * @brief Parse a recovered command body into sequence, tag, and setpoint.
 *
 * @param pt Pointer to the recovered command plaintext.
 * @param len Number of recovered plaintext bytes.
 * @param seq Pointer to store the little-endian sequence number.
 * @param tag Pointer to the 16-byte tag output buffer.
 * @param setpoint Pointer to store the decoded setpoint.
 * @return bool true when the body is well formed and in the guarded set.
 */
static bool control_parse(const uint8_t *pt, size_t len, uint32_t *seq,
                          uint8_t tag[CRYPTO_AEAD_TAG_LEN],
                          int16_t *setpoint) {
    if (!control_args_ok(pt, len, seq, tag, setpoint)) {
        return false;
    }
    *setpoint = control_get_i16(&pt[5]);
    if (!control_setpoint_ok(*setpoint)) {
        return false;
    }
    *seq = control_get_u32(pt);
    memcpy(tag, pt + 7u, CRYPTO_AEAD_TAG_LEN);
    return true;
}

/**
 * @brief Open one sealed command envelope under the field key.
 *
 * @param hex Pointer to the NUL-terminated hex envelope.
 * @param pt Pointer to the plaintext output buffer.
 * @param len Pointer to store the recovered plaintext length.
 * @return bool true when the envelope authenticated and opened.
 */
static bool control_open(const char *hex, uint8_t *pt, size_t *len) {
    uint8_t ad = (uint8_t)HVAC_NODE_ID;
    if (!g_control_key_ready || hex == NULL) {
        return false;
    }
    return envelope_open_hex(g_control_key, &ad, 1u, hex, pt,
                             ENVELOPE_MAX_PLAINTEXT, len);
}

/**
 * @brief Open and parse one sealed SETPOINT envelope.
 *
 * @param hex Pointer to the NUL-terminated hex envelope.
 * @param seq Pointer to store the recovered sequence number.
 * @param tag Pointer to the 16-byte tag output buffer.
 * @param setpoint Pointer to store the decoded setpoint.
 * @return bool true when the envelope opened and the body parsed.
 */
static bool control_decode(const char *hex, uint32_t *seq,
                           uint8_t tag[CRYPTO_AEAD_TAG_LEN],
                           int16_t *setpoint) {
    uint8_t pt[ENVELOPE_MAX_PLAINTEXT];
    size_t len;
    if (!control_open(hex, pt, &len)) {
        return false;
    }
    return control_parse(pt, len, seq, tag, setpoint);
}

void control_init(void) {
    g_control_key_ready = false;
    g_control_setpoint = HVAC_SAFE_SETPOINT_TENTHS;
    memset(g_control_key, 0, sizeof(g_control_key));
    hvac_auth_init(&g_control_auth);
    hvac_auth_set_key(NULL);
}

void control_deinit(void) {
    g_control_key_ready = false;
    hvac_auth_set_key(NULL);
}

bool control_set_key(const uint8_t key[CRYPTO_AEAD_KEY_LEN]) {
    if (key == NULL) {
        control_deinit();
        return false;
    }
    memcpy(g_control_key, key, CRYPTO_AEAD_KEY_LEN);
    g_control_key_ready = true;
    hvac_auth_set_key(g_control_key);
    return true;
}

bool control_authorize(uint32_t seq, const uint8_t tag[CRYPTO_AEAD_TAG_LEN]) {
    return hvac_auth_apply(&g_control_auth, seq, tag);
}

bool control_handle_frame(const char *hex) {
    uint32_t seq;
    uint8_t tag[CRYPTO_AEAD_TAG_LEN];
    int16_t setpoint;
    if (!control_decode(hex, &seq, tag, &setpoint) ||
        !control_authorize(seq, tag)) {
        return false;
    }
    g_control_setpoint = setpoint;
    return true;
}

int16_t control_setpoint(void) {
    return g_control_setpoint;
}
