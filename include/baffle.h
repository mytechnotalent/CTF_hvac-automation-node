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
// File:    baffle.h
// Desc:    Declares the HVAC baffle state machine that sequences the
//          SG90 actuator and fails safe on loss of authority.
// Created: 2026

#ifndef BAFFLE_H
#define BAFFLE_H

#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Bounded baffle travel time in milliseconds.
 */
#define BAFFLE_TRAVEL_MS 1000u

/**
 * @brief HVAC baffle position and health states.
 */
typedef enum baffle_state {
    /**
     * @brief Baffle is seated closed, the safe plant state.
     */
    BAFFLE_STATE_CLOSED = 0,
    /**
     * @brief Baffle is held fully open.
     */
    BAFFLE_STATE_OPEN = 1,
    /**
     * @brief Baffle has failed safe and is latched in fault.
     */
    BAFFLE_STATE_FAULT = 2,
    /**
     * @brief Baffle actuator is travelling between positions.
     */
    BAFFLE_STATE_MOVING = 3,
} baffle_state_t;

/**
 * @brief Initialize the baffle state machine and seat the baffle closed.
 *
 * @param void No parameters.
 * @return void
 */
void baffle_init(void);

/**
 * @brief Return the current baffle state.
 *
 * @param void No parameters.
 * @return baffle_state_t Current baffle state.
 */
baffle_state_t baffle_state(void);

/**
 * @brief Report whether the baffle is currently fully open.
 *
 * @param void No parameters.
 * @return bool true when the baffle is open.
 */
bool baffle_is_open(void);

/**
 * @brief Apply an authorized open or close command to the baffle.
 *
 * Unauthorized commands are refused. An authorized command starts a
 * bounded travel interval that baffle_tick completes. This is the guarded
 * command path that replaces the unauthenticated SETPOINT injection.
 *
 * @param open True to drive the baffle open, false to drive it closed.
 * @param authorized True when the caller has validated the command.
 * @return void
 */
void baffle_apply_command(bool open, bool authorized);

/**
 * @brief Advance the baffle state machine by one tick.
 *
 * Completes a pending travel once the bounded interval has elapsed.
 *
 * @param void No parameters.
 * @return void
 */
void baffle_tick(void);

/**
 * @brief Force the baffle closed and latch a fault.
 *
 * This is the fail-safe posture taken when the gateway link is lost or
 * the local override cannot be authorized.
 *
 * @param void No parameters.
 * @return void
 */
void baffle_fail_safe(void);

#endif // BAFFLE_H
