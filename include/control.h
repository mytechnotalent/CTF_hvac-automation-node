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
// File:    control.h
// Desc:    Declares the sealed SETPOINT command path that opens,
//          authorizes, and applies remote BMS commands.
// Created: 2026

#ifndef CONTROL_H
#define CONTROL_H

#include "crypto_aead.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief HVAC command code that carries a temperature SETPOINT.
 */
#define HVAC_COMMAND_SETPOINT 0x01u

/**
 * @brief Length in bytes of a sealed SETPOINT command body.
 *
 * The body is a little-endian 32-bit sequence, the guarded SETPOINT
 * command byte, a little-endian 16-bit setpoint in tenths of a degree
 * Celsius, and a 16-byte authenticated tag over the resulting
 * authorization record.
 */
#define CONTROL_COMMAND_LEN (4u + 1u + 2u + CRYPTO_AEAD_TAG_LEN)

/**
 * @brief Initialize the sealed SETPOINT command path.
 *
 * @param void No parameters.
 * @return void
 */
void control_init(void);

/**
 * @brief Clear the field key and reset the command path.
 *
 * @param void No parameters.
 * @return void
 */
void control_deinit(void);

/**
 * @brief Install the field key used to open and authorize commands.
 *
 * @param key Pointer to a 32-byte field key, or NULL to clear the key.
 * @return bool true when a key was installed.
 */
bool control_set_key(const uint8_t key[CRYPTO_AEAD_KEY_LEN]);

/**
 * @brief Authorize a command sequence and tag against the anti-replay window.
 *
 * @param seq Sequence number carried by the command.
 * @param tag Pointer to the 16-byte command tag to verify.
 * @return bool true when the command was accepted.
 */
bool control_authorize(uint32_t seq, const uint8_t tag[CRYPTO_AEAD_TAG_LEN]);

/**
 * @brief Open, authorize, and apply one sealed remote SETPOINT command.
 *
 * Rejects a malformed envelope, a forged tag, a replayed sequence, any
 * command byte outside the guarded SETPOINT set, and any setpoint outside
 * the safe provisioning band.
 *
 * @param hex Pointer to the NUL-terminated hex envelope.
 * @return bool true when the command authenticated and was applied.
 */
bool control_handle_frame(const char *hex);

/**
 * @brief Return the setpoint recovered from the last accepted command.
 *
 * @param void No parameters.
 * @return int16_t Setpoint in tenths of a degree Celsius.
 */
int16_t control_setpoint(void);

#endif // CONTROL_H
