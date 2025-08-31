# Port Scanner

A lightweight, cross-platform TCP port scanner implemented in Python. Use it to discover open services on a single host or across a range of ports with configurable timeouts, concurrency, and output options. Intended for quick diagnostics on networks you own or are authorized to test.

## Features
- TCP port scanning (single host or range)
- Concurrent scanning (threading/async)
- Customizable timeout and port range
- CSV/console output options

## Requirements
- Python 3.7+
- Standard library modules (socket, argparse, threading/asyncio)

## Installation
1. Clone the repo:
    ```
    git clone https://github.com/hamzeh01/port-scanner.git
    cd port-scanner
    ```
2. (Optional) Create a virtual environment:
    ```
    python -m venv venv
    source venv/bin/activate  # Windows: venv\Scripts\activate
    ```
3. Install dependencies (if any):
    ```
    pip install -r requirements.txt
    ```

## Usage

Basic syntax
```
python script.py -H <host> -p <ports> [options]
```

Common options to document (adjust to match `script.py`):
- `--host` / `-H` : target host (IP or hostname)
- `--ports` / `-p` : port or range (e.g., `22`, `1-1024`, `80,443,8000-9000`)
- `--timeout` / `-t` : connection timeout in seconds
- `--concurrency` / `-c` : number of worker threads/tasks
- `--output` / `-o` : output file path (CSV or JSON)
- `--verbose` / `-v` : enable verbose logging

## Examples
Scan common ports on a host:
```
python script.py -H example.com -p 22,80,443
```
Scan a range with higher concurrency:
```
python script.py -H 10.0.0.5 -p 1-1024 -c 100 -t 0.5
```

## Output
Document the output format produced by `script.py` (console layout, CSV columns, JSON schema). Example CSV columns:
```
host,port,status,service,latency_ms
```

## Notes & Safety
- Use only on networks and hosts you own or have permission to test.
- Scanning large ranges may be disruptive and slow.

## Contributing
- Fork, create a feature branch, add tests, and open a pull request.
- Document code behavior and CLI changes in this README.

## License

This project is licensed under the MIT License.
