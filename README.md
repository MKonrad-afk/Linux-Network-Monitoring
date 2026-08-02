# Linux Network Monitoring

A C++20 Linux security-monitoring tool that detects unusual outbound connections and authentication activity.

It combines Linux socket inspection, process attribution, AbuseIPDB reputation checks, structured JSONL logging, SSH brute-force detection, and optional local AI-assisted alert summaries.

## Features

- Monitors established TCP and UDP connections using `ss`
- Detects newly observed remote endpoints
- Associates connections with local processes when permissions allow it
- Filters loopback traffic
- Checks new untrusted IP addresses with AbuseIPDB
- Writes structured alerts to `alerts.jsonl`
- Tails `/var/log/auth.log` for relevant authentication events
- Detects `sudo` activity, successful SSH logins, and failed SSH logins
- Flags five failed SSH logins from one IP within five minutes as a HIGH alert
- Supports optional local AI summaries for HIGH SSH brute-force alerts through Ollama

## Example alert

```text
[HIGH][2026-08-02 17:29:28] Possible SSH brute-force attack from 203.0.113.10
              User: demo-user
              Failed attempts: 5 within 5 minutes.
              AI summary: The event may indicate repeated password guessing.
              Review authentication logs and investigate activity from this IP.
```

## Architecture

```text
Linux sockets and auth.log
            |
            v
   NetworkMonitor / AuthLogMonitor
            |
            v
      Detection rules
            |
            +----> AbuseIPDB reputation lookup
            |
            +----> Optional Ollama AI summary
            |
            v
      AlertLogger
            |
            +----> Terminal output
            +----> alerts.jsonl
```

## Requirements

- Linux
- C++20 compiler
- CMake
- `iproute2` (`ss` command)
- libcurl
- nlohmann/json

On Ubuntu:

```bash
sudo apt install build-essential cmake libcurl4-openssl-dev nlohmann-json3-dev iproute2
```

## Build

```bash
cmake -S . -B build
cmake --build build
```

Run:

```bash
./build/Linux-Network-Monitoring
```

## Configuration

The project reads sensitive values from environment variables. Do not place API keys in source code.

| Variable | Purpose |
| --- | --- |
| `ABUSEIPDB_API_KEY` | Optional AbuseIPDB API key for IP reputation scores |
| `OLLAMA_ENDPOINT` | Optional local Ollama API endpoint for AI summaries |


## Demo modes

Safe SSH brute-force demo:

```bash
./build/Linux-Network-Monitoring --demo-bruteforce
```

Local AI summary demo:

```bash
./build/Linux-Network-Monitoring --demo-ai
```

The demo IP `203.0.113.10` is reserved for documentation and is not a real attacker.

## AI-assisted triage

AI is optional and only enriches HIGH SSH brute-force alerts.

The detection logic remains rule-based. The model does not block traffic, change severity, or prove that an attack occurred. It provides a short analyst-style assessment and a suggested investigation step.

This project was tested with Ollama and `qwen2.5:1.5b` running locally.

## Limitations

- Process information may be unavailable for some sockets because of Linux permissions.
- Authentication log formats vary between Linux distributions.
- AI summaries are advisory and may be inaccurate.


