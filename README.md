# Scanropod

Scanropod is a lightweight orchestration tool for web application security scanners.
It exposes a REST API that allows users to start, monitor, stop and aggregate results
of security scans performed using multiple external DAST tools.

The project consists of:
- a backend server written in Go
- a CLI client written in Python
- external security scanners executed as subprocesses

Scanropod does not implement its own vulnerability detection logic. Instead, it
provides a unified interface for managing and aggregating results from existing tools.

---

## Functionality

The application exposes a REST API secured with an optional API key and HTTPS.
Using the API (directly or via the CLI client), the user can:

- start a new scan for one or multiple targets and select which scanners should be used
- check the status of a running or completed scan
- retrieve aggregated scan results in JSON format
- stop a running scan.

Scan execution is asynchronous. Each scan is assigned a unique identifier (`scan_id`)
that is later used to query its status or results.

---

## Supported scanners

Scanropod currently integrates the following DAST tools:

- [Nikto](https://github.com/sullo/nikto)
- [Nuclei](https://github.com/projectdiscovery/nuclei)
- [Wapiti](https://github.com/wapiti-scanner/wapiti)
- [OWASP ZAP](https://github.com/zaproxy)

---

## Requirements

### Runtime requirements (without Docker)

To run Scanropod without Docker, the following components are required:

- **Go** ≥ 1.21
- **Python** ≥ 3.12
- **Nikto** = 2.5.0
- **Nuclei** = 3.4.10
- **Wapiti** = 3.2.10
- **OWASP ZAP** = 2.16.1
- Linux-based operating system (tested on Ubuntu)

All scanners must be available in the system `PATH`.

---

## Running with Docker

The recommended way to run Scanropod is using Docker, as it eliminates the need to
manually install and configure external scanners.

### Build the image

```bash
docker build -t scanropods .
```

### Run the container

```bash
docker run --rm \
  −v /home/user/certs:/certs:ro \
  scanropods \
  --api-key secret \
  --https \
  --tls-cert /certs/server.crt \
  --tls-key /certs/server.key
```

## Running without Docker

### Build and run the server

```bash
go build -o scanropods
./scanropods --api-key secret --https --tls-cert cert.pem --tls-key key.pem
```

The server listens on port `8443` by default.

# CLI client

A Python-based CLI client is provided to simplify interaction with the API.

## Basic usage

```bash
scanropods_cli.py start \
  --target https://example.com \
  --api-key secret \
  --insecure
```

Available commands:
- `start` – start a new scan,
- `status` – check scan status,
- `result` – fetch scan results,
- `stop` – stop a running scan.

## Example results

After a scan is completed, the aggregated result can be retrieved in JSON format. [Example result](png/result/example1.json)

The aggregated report combines findings from all enabled scanners and maps them to CWE identifiers.

## To-Do
<!-- flags, order of mapping, REST -->