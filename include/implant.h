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
// File:    implant.h
// Desc:    Declares the SANDBOX_ONLY FROSTLINE implant: beacon, logic bomb,
//          rootkit hiding, anti-debug trap, and reserved-sector
//          persistence marker.
// Created: 2026

#ifndef IMPLANT_H
#define IMPLANT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Number of ticks between covert beacon transmissions.
 */
#define IMPLANT_BEACON_INTERVAL_TICKS 8u

/**
 * @brief Number of ticks between arming and the logic bomb trigger.
 */
#define IMPLANT_TRIGGER_DELAY_TICKS 3u

/**
 * @brief Length in bytes of the covert beacon magic preamble.
 */
#define IMPLANT_BEACON_MAGIC_LEN 4u

/**
 * @brief Length in bytes of the synthetic beacon status blob.
 */
#define IMPLANT_BEACON_BLOB_LEN 4u

/**
 * @brief Length in bytes of the fixed logic bomb arming command.
 */
#define IMPLANT_ARM_MAGIC_LEN 8u

/**
 * @brief Marker byte written into the reserved flash sector.
 */
#define IMPLANT_MARKER_BYTE 0xC7u

/**
 * @brief CoreDebug DHCSR bit that reports an enabled debugger.
 */
#define IMPLANT_DHCSR_DEBUGEN 0x00000001u

/**
 * @brief CoreDebug DHCSR bit that reports a halted core.
 */
#define IMPLANT_DHCSR_HALT 0x00000002u

/**
 * @brief Covert beacon magic preamble emitted to the local hub.
 */
extern const uint8_t IMPLANT_BEACON_MAGIC[IMPLANT_BEACON_MAGIC_LEN];

/**
 * @brief Fixed magic command that arms the logic bomb.
 */
extern const uint8_t IMPLANT_ARM_MAGIC[IMPLANT_ARM_MAGIC_LEN];

/**
 * @brief Initialize the implant and apply the reserved-sector state.
 *
 * The corrected build leaves the re-install gate clear, so a marker left
 * in the reserved flash sector does not re-arm the beacon or the bomb.
 *
 * @param void No parameters.
 * @return void
 */
void implant_init(void);

/**
 * @brief Advance the implant by one tick: beacon, rootkit, and bomb.
 *
 * @param void No parameters.
 * @return void
 */
void implant_tick(void);

/**
 * @brief Handle one inbound frame, arming the logic bomb on the magic.
 *
 * @param frame Pointer to the inbound frame bytes.
 * @param len Number of inbound frame bytes.
 * @return void
 */
void implant_handle_command(const uint8_t *frame, size_t len);

/**
 * @brief Report whether the logic bomb has been armed.
 *
 * @param void No parameters.
 * @return bool true when the logic bomb is armed.
 */
bool implant_armed(void);

/**
 * @brief Report whether a debug probe is attached via CoreDebug DHCSR.
 *
 * @param void No parameters.
 * @return bool true when C_DEBUGEN or C_HALT is set.
 */
bool implant_debug_attached(void);

/**
 * @brief Report whether the reserved-sector persistence marker is set.
 *
 * @param void No parameters.
 * @return bool true when the payload marker occupies the reserved sector.
 */
bool implant_persistence_present(void);

/**
 * @brief Report whether the rootkit is hiding the beacon from the node.
 *
 * The corrected build leaves the rootkit gate clear, so the beacon status
 * is visible on the LCD and the maintenance log.
 *
 * @param void No parameters.
 * @return bool true when the implant is masking its own beacon.
 */
bool implant_rootkit_active(void);

#endif // IMPLANT_H
