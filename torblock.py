#!/usr/bin/python3

# Block Tor Exit Nodes With Iptables
# Author: V. Alex Brennen <vab@mit.edu>
# License: This script is public domain
# Date: 2018-01-13
# Updated for Python 3 by: Sam Cleveland <samjcleveland@gmail.com>
#

# Description:  This script attempts to block all known tor exit nodes (as
#       reported by the Tor Project's website) from communicating
#       with the server that it is run on using iptables firewalling
#       rules.

import sys
import re
import requests
import subprocess
import ipaddress
import argparse

def parse_args():
    parser = argparse.ArgumentParser(description='TorBlock - Block Tor Exit Nodes with IPtables or Nginx.')
    parser.add_argument('server_ip', help='IP address of the server where the blocking will occur.')
    parser.add_argument('--nginx', metavar="Filename", type=argparse.FileType("a"), help='Filename to output the Nginx configuration file to.')
    return parser.parse_args()

# Execute iptables command to block a node after sanity checking
def block_iptables(ip):
    """Generate iptables entries for each tor exit node"""
    try:
        subprocess.check_call(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
    except OSError as e:
            if (e[0] == errno.EPERM):
                print("Since this script modifies the firewall with iptables it must be run with root privileges.", file=sys.stderr)
                sys.exit(1)
    print("Dropping all packets from " + ip)
    return True

def block_nginx(ip, output_file):
    """Outputs IP addresses in the Nginx 'deny' format"""
    output_file.write("deny {ip};\n".format(ip=ip))


# The main loop. It calls the blocknodes() function to attempt to open the
# file containing nodes to block, performs sanity checking, and then issues
# an iptables command to block a node. If it encounters a help request, it
# calls the usage() function to print the usage information and exit the
# program.
args = parse_args()

if not args.nginx:
    try:
        subprocess.check_call(['iptables', '-F', 'INPUT'])
    except OSError as e:
        if (e[0] == errno.EPERM):
            print("Since this script modifies the firewall with iptables it must be run with root privileges.", file=sys.stderr)
            sys.exit(1)

print("Retrieving list of nodes from Tor project website.")
ip_list_url = "https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip={server_ip}"

response = requests.get(ip_list_url.format(server_ip=args.server_ip), stream=True)

for line in response.iter_lines():
    if '#' in line.decode():
        continue

    try:
        ip = ipaddress.ip_address(line.decode().strip())
        if ip.is_private:
            print("Private IP address found. Skipping.")
            continue

        ip_network = ipaddress.ip_network(ip.exploded)
        ip_cidr = ip_network.exploded

    except ipaddress.AddressValueError as e:
        print("Invalid IP Address found. Skipping.")
        continue

    if args.nginx:
        block_nginx(ip_cidr, args.nginx)
    else:
        block_iptables(ip_cidr)
