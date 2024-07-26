# Nmapy

A simple Python-based port scanner that scans specified ports on given IP addresses. This tool can scan either a single IP address or a range of IP addresses.
It also supports using the top 100 or 1000 TCP ports and excluding specific IP addresses from the scan. This project is in a very early stage but I will be improving it over time.

## Features

- Scan specified ports on a single or multiple IP addresses.
- Use predefined top 100 or 1000 TCP ports for scanning.
- Exclude specific IP addresses from the scan.
- Graceful shutdown on receiving termination signals (SIGINT, SIGTERM).

## Requirements

- Python 3.x
- `termcolor` module

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/your-username/your-repository.git
    cd your-repository
    pip install -r requirements.txt
    ```

2. Ensure you have a `config.json` file in the root directory with the following structure:
    ```json
    {
        "default_ports_1000": [list of ports],
        "default_ports_100": [list of ports]
    }
    ```

## Usage

Run the port scanner with various options:

- **Scan specific ports on a single IP address:**
    ```bash
    python3 nmapy.py -p 80,443 192.168.1.1
    ```

- **Scan top 100 TCP ports on a single IP address:**
    ```bash
    python3 nmapy.py --top-100 192.168.1.1
    ```

- **Scan specific ports on multiple IP addresses:**
    ```bash
    python3 nmapy.py -p 80,443 --ip-range 192.168.1.1,192.168.1.2
    ```

- **Scan top 100 TCP ports on multiple IP addresses:**
    ```bash
    python3 nmapy.py --top-100 --ip-range 192.168.1.1,192.168.1.2
    ```

- **Exclude specific IP addresses from the scan:**
    ```bash
    python3 nmapy.py --ip-range 192.168.1.1,192.168.1.2 --exclude-ip 192.168.1.2
    ```

## License

This project is licensed under the MIT License.

## Contributing

Feel free to submit issues and enhancement requests. Pull requests are welcome.
