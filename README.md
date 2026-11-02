# Mini SOC – Real-Time Threat Detection & Incident Response Platform

A lightweight Security Operations Center (SOC) platform built with Python and Flask to monitor endpoint activity, detect suspicious behaviour, centralize security alerts, and manage incidents through a web-based dashboard.

## Project Overview

Mini SOC uses a centralized architecture:

- **MacBook endpoint:** Collects system telemetry, monitors network connections, detects suspicious activity, and generates security alerts.
- **Ubuntu SOC server:** Receives telemetry and alerts, stores records in SQLite, manages incidents, and provides a centralized dashboard.

## Architecture

```text
              MACBOOK ENDPOINT
        ┌──────────────────────────┐
        │    System Monitoring     │
        │    Network Monitoring    │
        │    Threat Detection      │
        │    Incident Management   │
        └────────────┬─────────────┘
                     │
             HTTP + API Key
                     │
                     ▼
              UBUNTU SOC SERVER
        ┌──────────────────────────┐
        │       Flask API          │
        │     SQLite Database     │
        │   Centralized Alerts    │
        │   Incident Management   │
        └────────────┬─────────────┘
                     │
                     ▼
              SOC WEB DASHBOARD
        ┌──────────────────────────┐
        │   Endpoint Monitoring    │
        │   Performance Charts     │
        │   Network Security       │
        │   Security Alerts        │
        │   Incident Response      │
        └──────────────────────────┘