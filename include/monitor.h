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
// File:    monitor.h
// Desc:    Declares the HVAC automation node state machine tying the
//          local override remote, sealed SETPOINT path, room climate
//          sensor, and BMS gateway link together.
// Created: 2026

#ifndef MONITOR_H
#define MONITOR_H

#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Infrared override remote code that requests the baffle open.
 */
#define MONITOR_IR_OVERRIDE_OPEN 0x47u

/**
 * @brief Infrared override remote code that requests the baffle closed.
 */
#define MONITOR_IR_OVERRIDE_CLOSE 0x45u

/**
 * @brief Infrared override remote code that clears a pending override.
 */
#define MONITOR_IR_OVERRIDE_CLEAR 0x46u

/**
 * @brief Number of monitor ticks between onboard heartbeat toggles.
 */
#define MONITOR_HEARTBEAT_TICKS 4u

/**
 * @brief Initialize the HVAC automation node state machine.
 *
 * Configures the I2C LCD, the DHT11 room climate sensor, the infrared
 * override remote, the annunciator LEDs, the baffle servo, the manual
 * override button, the RYLR998 radio, and derives the Argon2id field key.
 *
 * @param void No parameters.
 * @return bool true when all submodules initialized.
 */
bool monitor_init(void);

/**
 * @brief Clear the node-ready flag and command path.
 *
 * @param void No parameters.
 * @return void
 */
void monitor_deinit(void);

/**
 * @brief Clear a pending local override request.
 *
 * @param void No parameters.
 * @return void
 */
void monitor_clear_override(void);

/**
 * @brief Execute one HVAC automation node tick.
 *
 * Polls the override remote and the radio, verifies and applies sealed
 * SETPOINT commands, drives the baffle and LEDs, renders the BMS
 * status and setpoint, and fails safe on a lost gateway link.
 *
 * @param void No parameters.
 * @return bool true when the tick completed without a policy error.
 */
bool monitor_step(void);

#endif // MONITOR_H
