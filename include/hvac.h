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
// File:    hvac.h
// Desc:    Declares platform pin mapping, peripheral handles, and
//          provisioning boundaries for the IRON LUNG HVAC node.
// Created: 2026

#ifndef HVAC_H
#define HVAC_H

#include "hardware/i2c.h"
#include "hardware/uart.h"
#include "packet_artifact.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Onboard green LED GPIO pin number.
 *
 * The RP2350 Pico 2 onboard LED is connected to GPIO 25. It is blinked
 * whenever the controller completes a successful LoRa transmit.
 */
#define HVAC_LED_PIN 25u

/**
 * @brief DHT11 one-wire room climate sensor GPIO pin number.
 *
 * The DHT11 single data line reports the room temperature and humidity
 * that feed the BMS setpoint comparison.
 */
#define HVAC_DHT_PIN 4u

/**
 * @brief I2C peripheral used by the 1602 LCD backpack.
 *
 * The Pico 2 bus B (I2C1) drives the PCF8574 backpack on the display.
 */
#define HVAC_I2C i2c1

/**
 * @brief I2C SDA GPIO pin number.
 */
#define HVAC_I2C_SDA 2u

/**
 * @brief I2C SCL GPIO pin number.
 */
#define HVAC_I2C_SCL 3u

/**
 * @brief I2C bus clock rate in hertz.
 */
#define HVAC_I2C_BAUD 100000u

/**
 * @brief I2C address of the 1602 LCD PCF8574 backpack.
 */
#define HVAC_LCD_ADDR PACKET_LCD_I2C_ADDRESS

/**
 * @brief UART peripheral used by the RYLR998 transceiver.
 */
#define HVAC_UART uart1

/**
 * @brief UART TX GPIO pin number to the RYLR998 RX input.
 */
#define HVAC_UART_TX 8u

/**
 * @brief UART RX GPIO pin number from the RYLR998 TX output.
 */
#define HVAC_UART_RX 9u

/**
 * @brief UART baud rate negotiated with the RYLR998.
 */
#define HVAC_UART_BAUD 115200u

/**
 * @brief RYLR998 network identifier shared by all classroom radios.
 */
#define HVAC_NETWORK_ID 18u

/**
 * @brief Fixed command frame size in bytes.
 */
#define HVAC_FRAME_SIZE PACKET_FRAME_SIZE

/**
 * @brief Time to wait for a sealed SETPOINT before failing safe.
 */
#define HVAC_SETPOINT_WAIT_MS PACKET_SETPOINT_WAIT_MS

/**
 * @brief Servo pulse width in microseconds that seats the baffle closed.
 */
#define HVAC_SERVO_CLOSE_PULSE_US PACKET_SERVO_CLOSE_PULSE_US

/**
 * @brief Servo pulse width in microseconds that drives the baffle open.
 */
#define HVAC_SERVO_OPEN_PULSE_US PACKET_SERVO_OPEN_PULSE_US

/**
 * @brief Red alarm LED GPIO pin number.
 */
#define HVAC_RED_LED_PIN 16u

/**
 * @brief Yellow override-pending LED GPIO pin number.
 */
#define HVAC_YELLOW_LED_PIN 17u

/**
 * @brief Green nominal LED GPIO pin number.
 */
#define HVAC_GREEN_LED_PIN 18u

/**
 * @brief Manual override push-button GPIO pin number.
 */
#define HVAC_BUTTON_PIN 15u

/**
 * @brief Baffle actuator servo PWM GPIO pin number.
 */
#define HVAC_SERVO_PIN 14u

/**
 * @brief Infrared receiver GPIO pin number.
 */
#define HVAC_IR_PIN 5u

/**
 * @brief Lowest acceptable room temperature in tenths of a degree Celsius.
 */
#define HVAC_CLIMATE_MIN_TENTHS 0

/**
 * @brief Highest acceptable room temperature in tenths of a degree Celsius.
 */
#define HVAC_CLIMATE_MAX_TENTHS 400

/**
 * @brief Lowest accepted SETPOINT in tenths of a degree Celsius.
 */
#define HVAC_SETPOINT_MIN_TENTHS 50

/**
 * @brief Highest accepted SETPOINT in tenths of a degree Celsius.
 */
#define HVAC_SETPOINT_MAX_TENTHS 350

/**
 * @brief Fail-safe SETPOINT in tenths of a degree Celsius.
 *
 * When the gateway link is lost the node drives to this setpoint and
 * seats the baffle so an unattended plant does not run away.
 */
#define HVAC_SAFE_SETPOINT_TENTHS 200

/**
 * @brief Baffle deadband in tenths of a degree Celsius.
 *
 * The baffle only opens when the room rises this far above the setpoint
 * so the actuator does not chatter at the boundary.
 */
#define HVAC_BAFFLE_DEADBAND_TENTHS 5

/**
 * @brief Provisioned HVAC node identifier.
 */
#define HVAC_NODE_ID PACKET_NODE_ADDRESS

/**
 * @brief Provisioned BMS gateway LoRa address.
 */
#define HVAC_HUB_ADDRESS PACKET_HUB_ADDRESS

/**
 * @brief Offset of the reserved flash sector used by the staging marker.
 *
 * The final 4 KiB sector of the 4 MiB flash, well beyond the firmware.
 */
#define HVAC_IMPLANT_RESERVE_OFFSET 0x3FF000u

/**
 * @brief Reserved flash sector address used by the staging marker.
 */
#define HVAC_IMPLANT_RESERVE_ADDR 0x103FF000u

/**
 * @brief CoreDebug DHCSR register address used by the implant anti-debug.
 *
 * Bit 0 is C_DEBUGEN and bit 1 is C_HALT; either bit set means a debug
 * probe is attached.
 */
#define HVAC_IMPLANT_DHCSR_ADDR 0xE000EDF0u

#endif // HVAC_H
