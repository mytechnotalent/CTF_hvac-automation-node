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
// File:    baffle.c
// Desc:    Implements the HVAC baffle state machine that sequences the
//          SG90 actuator and fails safe on loss of authority.
// Created: 2026

#include "pico/time.h"
#include "baffle.h"
#include "servo.h"
#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Current baffle position and health state.
 */
static baffle_state_t g_baffle_state;

/**
 * @brief Pending travel target, true when the baffle is opening.
 */
static bool g_baffle_target_open;

/**
 * @brief Absolute time in microseconds when the pending travel completes.
 */
static uint64_t g_baffle_move_until_us;

/**
 * @brief Complete a pending travel by driving the actuator.
 *
 * @param void No parameters.
 * @return void
 */
static void baffle_complete(void) {
    if (g_baffle_target_open) {
        baffle_open();
        g_baffle_state = BAFFLE_STATE_OPEN;
        return;
    }
    baffle_close();
    g_baffle_state = BAFFLE_STATE_CLOSED;
}

void baffle_init(void) {
    g_baffle_target_open = false;
    g_baffle_state = BAFFLE_STATE_CLOSED;
    baffle_close();
}

baffle_state_t baffle_state(void) {
    return g_baffle_state;
}

bool baffle_is_open(void) {
    return g_baffle_state == BAFFLE_STATE_OPEN;
}

void baffle_apply_command(bool open, bool authorized) {
    if (!authorized) {
        return;
    }
    g_baffle_target_open = open;
    g_baffle_state = BAFFLE_STATE_MOVING;
    g_baffle_move_until_us = time_us_64() + (uint64_t)BAFFLE_TRAVEL_MS * 1000u;
}

void baffle_tick(void) {
    if (g_baffle_state != BAFFLE_STATE_MOVING) {
        return;
    }
    if (time_us_64() < g_baffle_move_until_us) {
        return;
    }
    baffle_complete();
}

void baffle_fail_safe(void) {
    baffle_close();
    g_baffle_target_open = false;
    g_baffle_state = BAFFLE_STATE_FAULT;
}
