# Scanropod - DAST Scanner Orchestrator

Scanropod is a lightweight orchestration tool for web application security scanners.
It exposes a REST API that allows users to start, monitor, stop and aggregate results
of security scans performed using multiple external DAST tools: [Nikto](https://github.com/sullo/nikto),
[Nuclei](https://github.com/projectdiscovery/nuclei), [Wapiti](https://github.com/wapiti-scanner/wapiti)
and [OWASP ZAP](https://github.com/zaproxy).

The project consists of a backend server written in Go and a CLI client written in Python.
Scanropod does not implement its own vulnerability detection logic - it provides a unified
interface for managing and aggregating results from existing tools, and maps findings to CWE identifiers.

## Installation

To install the tool, clone the repository from GitHub and build the server.

```bash
git clone https://github.com/kozlm/scanropod.git
cd scanropod
go build -o scanropod ./cmd/server
./scanropod -h
```

You should see a help message showing all server options:

```bash
options:
  -api-key string
    	API key for securing HTTP endpoints
  -https
    	Enable HTTPS
  -no-api-key
    	Disable API key authentication
  -tls-cert string
    	Path to TLS certificate
  -tls-key string
    	Path to TLS private key
```

A [`Makefile`](Makefile) is provided with `make build` and `make run` targets
as an alternative to the commands above. The `make docker` target builds the Docker image
(see [Starting with Docker](#starting-with-docker)).

The Python CLI client has no installation step - it only requires Python 3.12+ with the `requests` package (`pip install requests`).

## Starting a Server

The server listens on port `8443` and always requires an explicit decision about authentication:
you must pass either `--api-key` or `--no-api-key`. When an API key is set, every request must
include the `X-API-Key` header. HTTPS is optional and enabled with `--https`, which additionally
requires `--tls-cert` and `--tls-key`.

### Starting with HTTPS and API Key

Command:

```bash
./scanropod --api-key secret --https --tls-cert certs/cert.pem --tls-key certs/key.pem
```

Starts a TLS server, listening on `https://localhost:8443`.

### Starting without HTTPS and API Key

Command:

```bash
./scanropod --no-api-key
```

Starts a plain HTTP server, listening on `http://localhost:8443`.

### Starting with Docker

The recommended way to run Scanropod is Docker, as it eliminates the need to manually install
and configure external scanners - all four are preinstalled in the image.

```bash
make docker
docker run --rm \
  -p 8443:8443 \
  -v /home/user/certs:/certs:ro \
  scanropod \
  --api-key secret \
  --https \
  --tls-cert /certs/server.crt \
  --tls-key /certs/server.key
```

## Requirements (without Docker)

- **Go** ≥ 1.21
- **Python** ≥ 3.12
- **Nikto** = 2.5.0
- **Nuclei** = 3.4.10
- **Wapiti** = 3.2.10
- **OWASP ZAP** = 2.16.1

All scanners must be available in the system `PATH` (Linux-based OS, tested on Ubuntu).
Running with Docker (see [Starting with Docker](#starting-with-docker)) removes the need to install them manually.

## Usage

The API exposes four endpoints:

* `POST /scan/start` – start a new scan for one or multiple targets and select which scanners should be used,
* `GET /scan/status/:id` – check the status of a running or completed scan,
* `GET /scan/result/:id` – retrieve the aggregated scan result in JSON format,
* `POST /scan/stop/:id` – stop a running scan.

Scan execution is asynchronous. Each scan is assigned a unique identifier (`scan_id`)
that is later used to query its status or results. If the `scanners` field is omitted,
all four scanners are used.

### CLI Client

The CLI client offers commands mirroring the four API endpoints. All operations available
through the REST API (see [Testing and Examples](#testing-and-examples)) can also be performed
with the CLI client.

Available commands:

* `start` – start a new scan (`--target`, repeatable; `--targets-file`; `--scanner`, repeatable),
* `status` – check scan status,
* `result` – fetch scan results,
* `stop` – stop a running scan.

Global CLI options: `--base-url` (default `https://localhost:8443`), `--api-key`, `--insecure`
(skip TLS certificate verification for self-signed certs).

#### `start` command

```bash
./scanropod_cli.py start \
  --target http://192.168.0.156/DVWA/vulnerabilities/xss_r/ \
  --scanner nikto --scanner zap \
  --base-url http://localhost:8443
```

Multiple targets can be passed either by repeating `--target` or via a file with one URL per line (`--targets-file`).

#### `status` command

```bash
./scanropod_cli.py status e9b0e8b8-9c1d-4d0f-8a5b-2cd4c3f498a2 --api-key secret --insecure
```

Prints the scan status object, pretty-printed. Possible statuses: `running`, `done`, `failed`, `stopped`.

#### `result` command

```bash
./scanropod_cli.py result e9b0e8b8-9c1d-4d0f-8a5b-2cd4c3f498a2 --api-key secret --insecure
```

#### `stop` command

```bash
./scanropod_cli.py stop e9b0e8b8-9c1d-4d0f-8a5b-2cd4c3f498a2 --api-key secret --insecure
```

## Project Structure

### Directories

* `cmd/server` – application entrypoint
* `internal` – source code (`server`, `scanner`, `report`, `store`, `model`)
* `config` – scanner configurations and CWE CSV mappings
* `png` – example results, HTTP request files and screenshots

## Testing and Examples

The examples below show plain HTTP requests and responses for each API endpoint
(the same operations can be performed with the CLI client, see [Usage](#usage)).

### Starting a scan

**Request**:

```http request
POST http://localhost:8443/scan/start
Content-Type: application/json
X-API-Key: secret

{
  "targets": ["http://192.168.0.156/DVWA/vulnerabilities/xss_r/"],
  "scanners": ["nikto", "zap"]
}
```

**Response**:

```json
{"scan_id": "e9b0e8b8-9c1d-4d0f-8a5b-2cd4c3f498a2"}
```

### Checking scan status

Possible statuses: `running`, `done`, `failed`, `stopped`.

**Request**:

```http request
GET http://localhost:8443/scan/status/e9b0e8b8-9c1d-4d0f-8a5b-2cd4c3f498a2
X-API-Key: secret
```

**Response**:

```json
{
  "id": "e9b0e8b8-9c1d-4d0f-8a5b-2cd4c3f498a2",
  "targets": ["http://192.168.0.156/DVWA/vulnerabilities/xss_r/"],
  "scanners": ["nikto", "zap"],
  "started_at": "2026-01-04T18:26:02.482267282+01:00",
  "status": "running"
}
```

### Fetching aggregated result

The aggregated result can be retrieved in JSON format after a scan is completed.
[Example result](png/result/example1.json)

The aggregated report combines findings from all enabled scanners and maps them
to CWE identifiers using the CSV files from `config/cwe-lists`.

**Request**:

```http request
GET http://localhost:8443/scan/result/e9b0e8b8-9c1d-4d0f-8a5b-2cd4c3f498a2
X-API-Key: secret
```

### Stoping a running scan

Stopping a scan that has already finished returns `409 Conflict`.

**Request**:

```http request
POST http://localhost:8443/scan/stop/e9b0e8b8-9c1d-4d0f-8a5b-2cd4c3f498a2
X-API-Key: secret
```

**Response**:

```json
{
  "id": "e9b0e8b8-9c1d-4d0f-8a5b-2cd4c3f498a2",
  "targets": ["http://192.168.0.156/DVWA/vulnerabilities/xss_r/"],
  "scanners": ["nikto", "zap"],
  "started_at": "2026-01-04T18:26:02.482267282+01:00",
  "status": "stopped"
}
```
