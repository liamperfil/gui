#!/usr/bin/env python3
# Copyright (c) 2013-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Generate seeds.txt from Pieter's DNS seeder
#

import argparse
import collections
import ipaddress
from pathlib import Path
import random
import re
import sys
from typing import Union, Optional

# Add the asmap directory to sys.path to import the asmap module
asmap_dir = Path(__file__).parent.parent / "asmap"
sys.path.append(str(asmap_dir))
from asmap import ASMap, net_to_prefix  # noqa: E402

# --- Configuration Constants ---
NSEEDS = 512

MAX_SEEDS_PER_ASN = {
    'ipv4': 2,
    'ipv6': 10,
}

MIN_BLOCKS = 868000

# Minimum uptime requirements for each network type
REQ_UPTIME = {
    'ipv4': 50,
    'ipv6': 50,
    'onion': 50,
    'i2p': 50,
    'cjdns': 10,
}

# --- Compiled Regular Expressions ---
PATTERN_IPV4 = re.compile(r"^(([0-2]?\d{1,2})\.([0-2]?\d{1,2})\.([0-2]?\d{1,2})\.([0-2]?\d{1,2})):(\d{1,5})$")
PATTERN_IPV6 = re.compile(r"^\[([\da-f:]+)]:(\d{1,5})$", re.IGNORECASE)
PATTERN_ONION = re.compile(r"^([a-z2-7]{56}\.onion):(\d+)$")
PATTERN_I2P = re.compile(r"^([a-z2-7]{52}\.b32\.i2p):(\d{1,5})$")
# User agent pattern: Updated to include 29.0 and 30.0 as valid versions
PATTERN_AGENT = re.compile(
    r"^/Satoshi:("
    r"0\.14\.(0|1|2|3|99)"
    r"|0\.15\.(0|1|2|99)"
    r"|0\.16\.(0|1|2|3|99)"
    r"|0\.17\.(0|0\.1|1|2|99)"
    r"|0\.18\.(0|1|99)"
    r"|0\.19\.(0|1|2|99)"
    r"|0\.20\.(0|1|2|99)"
    r"|0\.21\.(0|1|2|99)"
    r"|22\.(0|1|99)\.0"
    r"|23\.(0|1|2|99)\.0"
    r"|24\.(0|1|2|99)\.(0|1)"
    r"|25\.(0|1|2|99)\.0"
    r"|26\.(0|1|2|99)\.0"
    r"|27\.(0|1|2|99)\.0"
    r"|28\.(0|1|99)\.0"
    r"|29\.(0|1|99)\.0"  # New version
    r"|30\.(0|1|99)\.0"  # New version
    r")")

def parseline(line: str) -> Optional[dict]:
    """ Parses a line from `seeds_main.txt` into a dictionary of details,
    or `None` if the line could not be parsed.
    """
    if line.startswith('#'):
        return None

    sline = line.split()
    if len(sline) < 11:
        return None

    # Ignore bad results (uptime 0 or other seeder-reported error conditions).
    if int(sline[1]) == 0:
        return None

    ip_matchers = [
        ('ipv4', PATTERN_IPV4),
        ('ipv6', PATTERN_IPV6),
        ('onion', PATTERN_ONION),
        ('i2p', PATTERN_I2P),
    ]

    net = None
    ipstr = None
    port = None
    sortkey = None
    ip_num = None

    for net_type, pattern in ip_matchers:
        m = pattern.match(sline[0])
        if m:
            net = net_type
            if net == 'ipv4':
                ipstr = m.group(1)
                port = int(m.group(6))
                parts = [int(m.group(i + 2)) for i in range(4)]
                if any(p < 0 or p > 255 for p in parts):
                    return None
                ip_num = sum(parts[i] << (8 * (3 - i)) for i in range(4))
                if ip_num == 0:
                    return None
                sortkey = ip_num
            elif net == 'ipv6':
                ipstr = m.group(1)
                port = int(m.group(2))
                if ipstr == '::':  # Ignore localhost
                    return None
                if ipstr.lower().startswith("fc"):  # cjdns looks like ipv6 but starts with fc
                    net = "cjdns"
                sortkey = ipstr
            else: # onion or i2p
                ipstr = m.group(1)
                port = int(m.group(2))
                sortkey = ipstr
            break
    else: # No regex matched
        return None

    # Extract common data
    uptime30 = float(sline[7][:-1])
    lastsuccess = int(sline[2])
    version = int(sline[10])
    agent = sline[11][1:-1]
    service = int(sline[9], 16)
    blocks = int(sline[8])

    return {
        'net': net,
        'ip': ipstr,
        'port': port,
        'ipnum': ip_num, # Will be None for non-IPv4
        'uptime': uptime30,
        'lastsuccess': lastsuccess,
        'version': version,
        'agent': agent,
        'service': service,
        'blocks': blocks,
        'sortkey': sortkey,
    }

def dedup(ips: list[dict]) -> list[dict]:
    """ Removes duplicates from `ips` where multiple IPs share address and port. """
    d = {}
    for ip in ips:
        # Use a tuple (ip, port) as key to ensure uniqueness
        d[(ip['ip'], ip['port'])] = ip
    return list(d.values())

def filtermultiport(ips: list[dict]) -> list[dict]:
    """ Filters out hosts with more than one node per IP (likely abusive). """
    hist = collections.defaultdict(list)
    for ip in ips:
        hist[ip['sortkey']].append(ip)
    # Return only the first IP for those with only one entry (not multiple ports)
    return [value[0] for value in hist.values() if len(value) == 1]

def filterbyasn(asmap: ASMap, ips: list[dict], max_per_asn: dict, max_per_net: int) -> list[dict]:
    """ Prunes `ips` to have at most `max_per_net` IPs from each network type (ipv4, ipv6)
    and at most `max_per_asn` IPs from each ASN within each network.
    """
    ips_ipv46 = [ip for ip in ips if ip['net'] in ['ipv4', 'ipv6']]
    ips_other = [ip for ip in ips if ip['net'] in ['onion', 'i2p', 'cjdns']]

    result = []
    net_count: dict[str, int] = collections.defaultdict(int)
    asn_count: dict[tuple[str, int], int] = collections.defaultdict(int)

    # Process IPv4 and IPv6 based on ASN and network limits
    for ip in ips_ipv46:
        if net_count[ip['net']] >= max_per_net:
            continue # Already reached the limit for this network

        try:
            # Ensure the IP address is a valid ipaddress.ip_network object.
            # If ip['ip'] is an IPv4 address like '192.0.2.1', ipaddress.ip_network(ip['ip'])
            # will treat it as '192.0.2.1/32'.
            # If it's an IPv6 address like '2001:db8::1', it will treat it as '2001:db8::1/128'.
            # asmap.lookup expects an ip_network object or prefix.
            network_obj = ipaddress.ip_network(ip['ip'], strict=False) # strict=False allows host addresses
            asn = asmap.lookup(net_to_prefix(network_obj))
        except ValueError:
            # In case of an invalid IP address, treat as if it has no ASN
            asn = None

        if asn is None:
            # If no ASN (not found in asmap or invalid IP),
            # it can still be added if it doesn't violate the network limit,
            # but it won't be limited by ASN.
            if net_count[ip['net']] < max_per_net:
                net_count[ip['net']] += 1
                result.append(ip)
            continue # Move to the next IP

        if asn_count[(ip['net'], asn)] >= max_per_asn[ip['net']]:
            continue # Already reached the limit for this ASN on this network

        asn_count[(ip['net'], asn)] += 1
        net_count[ip['net']] += 1
        ip['asn'] = asn
        result.append(ip)

    # Add back Onions, I2P, and CJDNS (up to max_per_net for each)
    # These are currently not filtered by ASN.
    for ip_type in ['onion', 'i2p', 'cjdns']:
        count = 0
        for ip in ips_other:
            if ip['net'] == ip_type:
                if count < max_per_net:
                    result.append(ip)
                    count += 1

    return result

def ip_stats(ips: list[dict]) -> str:
    """ Formats and returns a pretty string with IP statistics. """
    hist: dict[str, int] = collections.defaultdict(int)
    for ip in ips:
        hist[ip['net']] += 1

    return f"{hist['ipv4']:6d} {hist['ipv6']:6d} {hist['onion']:6d} {hist['i2p']:6d} {hist['cjdns']:6d}"

def parse_args():
    """ Parses command-line arguments. """
    argparser = argparse.ArgumentParser(description='Generate a list of bitcoin node seed ip addresses.')
    argparser.add_argument("-a","--asmap", help='the location of the asmap ASN database file (required)', required=True)
    argparser.add_argument("-s","--seeds", help='the location of the DNS seeds file (required)', required=True)
    argparser.add_argument("-m", "--minblocks", help="The minimum number of blocks each node must have", default=MIN_BLOCKS, type=int)
    return argparser.parse_args()

def main():
    args = parse_args()

    print(f'Loading asmap database "{args.asmap}"…', end='', file=sys.stderr, flush=True)
    try:
        with open(args.asmap, 'rb') as f:
            asmap = ASMap.from_binary(f.read())
        print('Done.', file=sys.stderr)
    except FileNotFoundError:
        print(f"Error: Asmap file '{args.asmap}' not found.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error loading asmap: {e}", file=sys.stderr)
        sys.exit(1)

    print('Loading and parsing DNS seeds…', end='', file=sys.stderr, flush=True)
    try:
        with open(args.seeds, 'r', encoding='utf8') as f:
            lines = f.readlines()
        ips = [parseline(line) for line in lines]
        random.shuffle(ips) # Shuffle so that ASN selection isn't always from the same ranges
        print('Done.', file=sys.stderr)
    except FileNotFoundError:
        print(f"Error: Seeds file '{args.seeds}' not found.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error loading seeds: {e}", file=sys.stderr)
        sys.exit(1)

    print('\x1b[7m  IPv4   IPv6  Onion    I2P  CJDNS Pass                                               \x1b[0m', file=sys.stderr)
    print(f'{ip_stats(ips):s} Initial', file=sys.stderr)

    # Filters
    # Skip entries with invalid address or parsing issues.
    ips = [ip for ip in ips if ip is not None]
    print(f'{ip_stats(ips):s} Skip entries with invalid address', file=sys.stderr)

    # Skip duplicates (in case multiple seeds files were concatenated)
    ips = dedup(ips)
    print(f'{ip_stats(ips):s} After removing duplicates', file=sys.stderr)

    # Enforce minimal number of blocks.
    ips = [ip for ip in ips if ip['blocks'] >= args.minblocks]
    print(f'{ip_stats(ips):s} Enforce minimal number of blocks ({args.minblocks})', file=sys.stderr)

    # Require service bit 1 (NODE_NETWORK).
    ips = [ip for ip in ips if (ip['service'] & 1) == 1]
    print(f'{ip_stats(ips):s} Require service bit 1 (NODE_NETWORK)', file=sys.stderr)

    # Require minimum uptime.
    ips = [ip for ip in ips if ip['uptime'] > REQ_UPTIME[ip['net']]]
    print(f'{ip_stats(ips):s} Require minimum uptime', file=sys.stderr)

    # Require a known and recent user agent.
    ips = [ip for ip in ips if PATTERN_AGENT.match(ip['agent'])]
    print(f'{ip_stats(ips):s} Require a known and recent user agent', file=sys.stderr)

    # Sort by availability (and use last success as tie breaker)
    ips.sort(key=lambda x: (x['uptime'], x['lastsuccess'], x['ip']), reverse=True)

    # Filter out hosts with multiple bitcoin ports, these are likely abusive
    ips = filtermultiport(ips)
    print(f'{ip_stats(ips):s} Filter out hosts with multiple bitcoin ports', file=sys.stderr)

    # Look up ASNs and limit results, both per ASN and globally.
    # NSEEDS is the global limit for combined IPv4/IPv6, but other types are added afterwards.
    ips = filterbyasn(asmap, ips, MAX_SEEDS_PER_ASN, NSEEDS)
    print(f'{ip_stats(ips):s} Look up ASNs and limit results per ASN and per net', file=sys.stderr)

    # Sort the results by IP address (for deterministic output).
    ips.sort(key=lambda x: (x['net'], x['sortkey']))

    # Print formatted results
    for ip in ips:
        if ip['net'] in ('ipv6', 'cjdns'):
            print(f"[{ip['ip']}]:{ip['port']}", end="")
        else:
            print(f"{ip['ip']}:{ip['port']}", end="")
        if 'asn' in ip:
            print(f" # AS{ip['asn']}", end="")
        print()

if __name__ == '__main__':
    main()