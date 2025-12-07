System prompt for LLMs interacting with the ESP32_olimex_anchore repository
Purpose

This repository contains the firmware of an ESP32-based UWB IPS Anchor Gateway.
The system bridges communication between:

an ESP32 Ethernet board (Olimex hardware),

and a UWB anchor module (via BLE),

encrypts outgoing IPS data using AES-CTR, and forwards them via UDP/Ethernet to backend IPS servers.

This document serves as a system prompt for AI models so they can correctly interpret the repository’s architecture, components, data flow and configuration mechanisms.

High-level overview

The firmware acts as a gateway, not as a positioning engine.
Its core responsibilities:

Receive UWB data via BLE (TLV format)

Decode, log, and format the data

Encrypt using AES-CTR

Send to backend servers via Ethernet (UDP)

Provide configuration interfaces:

Web UI (admin + super user)

REST API

BLE-based configuration CLI (JSON → TLV)

NVS persistent storage

Repository architecture
1. main/

Entrypoint of the firmware.
Handles system startup:

NVS initialization

Global configuration loading

Ethernet initialization

SPIFFS mounting

Webserver startup

BLE subsystem startup

UWB configuration CLI initialization

app_main() defines the complete boot sequence and orchestrates all components.

2. globals/

Stores the system’s persistent and runtime configuration:

Network settings (DHCP/static)

IPS configuration (up to 3 IP targets)

Device metadata (zone, device name, etc.)

Last UWB status and metrics

Accessible across modules.

3. components/ethernet/

Responsible for:

Ethernet PHY/MAC initialization

Link state handling

UDP socket management

Packet transmission

Contains ethernet_sender, which uses aes_sender to encrypt payloads before sending.

4. components/key_storage/

Secure AES key handling.

Saves AES key in NVS

Loads into memory when needed

Key format: 32-byte hex (128-bit AES)

Used exclusively by the AES sender.

5. components/ble/

Implements BLE transport for the UWB module.

Scanning / connection

GATT service+characteristic handling

TLV parsing

Pretty-print logs

Forwarding UWB data to AES sender

BLE is the sole channel through which UWB data and configuration interact with the ESP32.

6. components/webserver/

Contains:

HTTP server

REST API endpoints

Static file hosting (SPIFFS)

UWB CLI wrapper for web-based configuration

System statistics reporting

Frontend pages include:

admin.html – network & IPS configuration

super_user.html – BLE/UWB details, advanced settings

web_stats.html – runtime system metrics

7. components/uwb_cfg_cli/

Converts JSON-based web configuration into TLV messages and sends them via BLE:

UWB network parameters (IDs, delays, sync tuning)

UWB PHY parameters (channel, PRF, STS, codes)

Log-levels and diagnostic settings

This is the primary control path for configuring the UWB module.

Data Flow Summary

UWB module broadcasts TLV packets over BLE.

BLE component receives, decodes, logs.

Data forwarded to AES sender.

AES-CTR encrypts the payload, prepends IV.

UDP sender transmits encrypted payload to backend servers.

Configuration Interfaces

The system supports 3 complementary configuration channels:

A) Web UI (Admin / Super User)

Network parameters

IPS destinations

BLE configuration

UWB configuration

AES key management

Status & logs

B) BLE-based UWB CLI

Full control of UWB internal parameters

Low-level PHY & sync settings

C) NVS (persistent)

Stores:

AES key

network config

IPS destinations

BLE identifiers

Build system

Uses ESP-IDF 5.3.x

CMake-based component architecture

SPIFFS frontend image auto-generated during build

Standard build sequence:

idf.py set-target esp32
idf.py build
idf.py flash monitor

AI Interpretation Requirements
The AI must:

Distinguish clearly between:

BLE (UWB transport)

Ethernet (uplink UDP)

AES encryption layer

Understand the JSON → TLV BLE configuration pipeline

Explain or reason about components independently

Track the global flow: BLE → parsing → AES → UDP

Avoid assumptions not present in the code

The AI must NOT:

Misinterpret the firmware as a positioning algorithm

Infer nonexistent protocols or backend formats

Treat AES-CTR as authenticated or integrity-protected

Conflate BLE control-path with IPS network transport

Conceptual model

The firmware is best understood as:

“A modular, embedded gateway between a UWB anchor and an IPS backend, featuring BLE configuration, encrypted UDP forwarding, and a web-based management interface.”

This prompt provides the minimal but complete conceptual framework for accurate interpretation of the repository.
