import socket
import json
import sys
import logging
import signal
import argparse
import os
from termcolor import colored

def signal_handler(sig, frame):
    logging.info(colored('[*] Received shutdown signal, exiting...', 'red'))
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

config_path = 'config.json'
if not os.path.isfile(config_path):
    raise FileNotFoundError(colored(f"[-] Configuration file not found: {config_path}", 'red'))

with open(config_path) as config_file:
    config = json.load(config_file)

required_keys = {'default_ports_1000', 'default_ports_100'}
if not required_keys.issubset(config.keys()):
    raise ValueError(colored(f"[-] Configuration file must contain keys: {required_keys}", 'red'))

def scan(address, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((address, port))
        print(colored(f"[+] Port {port} is open on {address}", 'green'))
        sock.close()
    except Exception as e:
        print(colored(f"[-] Port {port} is not open on {address}: {e}", 'red'))

def main():

    parser = argparse.ArgumentParser(description='Python Port Scanner')
    parser.add_argument('-p', type=str, help='[*] Specify ports to scan, separated by commas')
    parser.add_argument('--top-100', action='store_true', help='[*] Use top 100 TCP ports')
    parser.add_argument('--exclude-ip', type=str, help='[*] Exclude IP address from range')
    parser.add_argument('--ip-range', type=str, help='[*] List multiple IP addresses')
    parser.add_argument('ip', nargs='?', type=str, help='[*] Target IP address')

    args = parser.parse_args()

    if not args.ip and not args.ip_range:
        parser.error(colored("[-] No IP address specified.", 'red'))

    addresses = []
    if args.ip:
        addresses.append(args.ip)
    elif args.ip_range:
        addresses.extend(args.ip_range.split(','))
    
    if len(addresses) == 0:
        parser.error(colored("[-] No addresses specified"), 'red')
        sys.exit(0)

    if args.exclude_ip:
        if not args.ip_range:
            parser.error(colored("[-] Can only use --exclude-ip with --ip-range parameter.", 'red'))
        exclusions = args.exclude_ip.split(',')
        addresses = [ip for ip in addresses if ip not in exclusions]

    if len(addresses) == 0:
        logging.error(colored("[-] No addresses found.", 'red'))
        sys.exit(0)

    if args.p:
        ports = [int(port) for port in args.p.split(',')]
    elif args.top_100:
        ports = config['default_ports_100']
    else:
        ports = config['default_ports_1000']

    if len(ports) == 0:
        logging.error(colored("[-] No ports found.", 'red'))
        sys.exit(0)

    for address in addresses:
        for port in ports:
            scan(address, port)

if __name__ == '__main__':
    try:
        logging.info(colored("[*] Starting port scanner", 'blue'))
        main()
    except Exception as e:
        print(colored(f'[-]Encountered an error: {e}', 'red'))
    finally:
        print(colored("[*] Scan finished.", 'blue'))