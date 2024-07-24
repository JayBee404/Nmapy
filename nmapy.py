import socket
import json
from datetime import datetime
import sys
import logging
import signal
import argparse
import os

def signal_handler(sig, frame):
    logging.info('Received shutdown signal, exiting...')
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

config_path = 'config.json'
if not os.path.isfile(config_path):
    raise FileNotFoundError(f"Configuration file not found: {config_path}")

with open(config_path) as config_file:
    config = json.load(config_file)

required_keys = {'default_ports'}
if not required_keys.issubset(config.keys()):
    raise ValueError(f"Configuration file must contain keys: {required_keys}")

def scan(address, port):
    try:
        sock = socket.socket()
        sock.connect((address, port))
        print("[+] Port Opened " + str(port))
        sock.close()
    except Exception:
        pass

def main():

    ports = []
    addresses = []
    exclusions = []
    
    parser = argparse.ArgumentParser(description='Python Port Scanner')
    #parser.add_argument('-sV', action='store_true', help='Perform a service scan') - look into scapy and nmap libraries
    parser.add_argument('-p', type=str, help='Specify ports to scan, separated by commas')
    parser.add_argument('--exclude-ip', type=str, help='Exclude IP address from range')
    parser.add_argument('--ip-range', type=str, help='List multiple IP addresses')
    parser.add_argument('ip', nargs='?', type=str, help='Target IP address')

    args = parser.parse_args()

    if not args.ip and not args.iprange:
        parser.error("No IP address specified.")

    if args.ip:
        addresses.append(args.ip)
    elif args.ip_range:
        addresses.append(args.iprange.split(','))

    if args.exclude_ip:
        if not args.ip_range:
            parser.error("Can only use --exclude-ip with --ip-range parameter.")
        else:
             addresses = [ip for ip in addresses if ip not in exclusions]

    if len(addresses) == 0:
        logging.error("No addresses found.")
        sys.exit(0)

    if args.ports:
        ports.append(args.ports.split(','))
    else:
        ports = config['default_ports']
    
    if len(ports) == 0:
        logging.error("No addresses found.")
        sys.exit(0)

    for address in addresses:
        for port in ports:
            scan(address, port)


if __name__ == '__main__':
    try:
        logging.info("Starting port scanner")
        main()
    except Exception as e:
        print(f'Encountered an error: {e}')
    finally:
        print("Scan finished.")




#def scan(target, ports):
#	print('\n' + ' Starting Scan For ' + str(target))
#	for port in range(1,ports):
#		scan_port(target,port)


#def scan_port(ipaddress, port):
#	try:
#		sock = socket.socket()
#		sock.connect((ipaddress, port))
#		print("[+] Port Opened " + str(port))
#		sock.close()
#	except Exception as e:
		
#		pass


#targets = input("[*] Enter Targets To Scan(split them by ,): ")
#ports = int(input("[*] Enter How Many Ports You Want To Scan: "))
#if ',' in targets:
#	print(termcolor.colored(("[*] Scanning Multiple Targets"), 'green'))
#	for ip_addr in targets.split(','):
#		scan(ip_addr.strip(' '), ports)
#else:
#	scan(targets,ports)