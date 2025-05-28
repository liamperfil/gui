#!/usr/bin/env python3
# Copyright (c) 2014-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
'''
Script to generate list of seed nodes for kernel/chainparams.cpp.

This script expects four text files in the directory that is passed as an
argument:

    nodes_main.txt
    nodes_signet.txt
    nodes_test.txt
    nodes_testnet4.txt

These files must consist of lines in the format:

    <ip>:<port>
    [<ipv6>]:<port>
    <onion>.onion:<port>
    <i2p>.b32.i2p:<port>

The output will be several data structures with the peers in binary format,
suitable for inclusion in `src/chainparamsseeds.h`.
'''

from base64 import b32decode
from enum import Enum
import sys
import os
import re

class BIP155Network(Enum):
    """
    Enum representing the network types as defined in BIP155.
    Each enum member has a corresponding integer value.
    """
    IPV4 = 1
    IPV6 = 2
    TORV2 = 3  # Tor v2 addresses are no longer supported
    TORV3 = 4
    I2P = 5
    CJDNS = 6

def name_to_bip155(addr):
    '''
    Convert an address string to a BIP155 (networkID, addr_bytes) tuple.
    Raises ValueError if the address format is unrecognized or invalid.
    '''
    if addr.endswith('.onion'):
        # Decode base32 Tor address.
        vchAddr = b32decode(addr[0:-6], True)
        if len(vchAddr) == 35:
            # Tor v3 address (32 bytes public key + 1 byte checksum + 2 bytes version).
            assert vchAddr[34] == 3  # Check for Tor v3 version byte.
            return (BIP155Network.TORV3, vchAddr[:32])
        elif len(vchAddr) == 10:
            # Tor v2 address (no longer supported).
            return (BIP155Network.TORV2, vchAddr)
        else:
            raise ValueError(f'Invalid onion address length: {len(vchAddr)} bytes for {addr}')
    elif addr.endswith('.b32.i2p'):
        # Decode base32 I2P address. '====' padding is added for b32decode.
        vchAddr = b32decode(addr[0:-8] + '====', True)
        if len(vchAddr) == 32:
            return (BIP155Network.I2P, vchAddr)
        else:
            raise ValueError(f'Invalid I2P address length: {len(vchAddr)} bytes for {addr}')
    elif '.' in addr: # Likely an IPv4 address.
        # Convert IPv4 string to bytes.
        return (BIP155Network.IPV4, bytes((int(x) for x in addr.split('.'))))
    elif ':' in addr: # Likely an IPv6 or CJDNS address.
        sub = [[], []] # Used to store parsed components before and after '::'.
        x = 0 # Index for `sub`, 0 for prefix, 1 for suffix after '::'.
        addr_parts = addr.split(':')

        for i, comp in enumerate(addr_parts):
            if comp == '':
                # Handle '::' which represents a run of zero-value 16-bit blocks.
                if i == 0 or i == (len(addr_parts) - 1):
                    # Skip empty components at the beginning or end (e.g., "::1" or "1::").
                    continue
                x += 1 # Move to the suffix part.
                assert x < 2 # Ensure only one '::' is present.
            else:
                # Convert hexadecimal component to two bytes.
                val = int(comp, 16)
                sub[x].append(val >> 8)
                sub[x].append(val & 0xff)

        # Calculate number of null bytes needed for '::'.
        nullbytes = 16 - len(sub[0]) - len(sub[1])
        # Assertions for correct handling of '::'.
        assert (x == 0 and nullbytes == 0) or \
               (x == 1 and nullbytes > 0), \
               f"Malformed IPv6/CJDNS address: {addr}"

        # Combine prefix, null bytes, and suffix into a 16-byte address.
        addr_bytes = bytes(sub[0] + ([0] * nullbytes) + sub[1])

        # Check for CJDNS address range (fc00::/8).
        if addr_bytes[0] == 0xfc:
            # Assume that seeds with fc00::/8 addresses belong to CJDNS,
            # not to the publicly unroutable "Unique Local Unicast" network, see
            # RFC4193: https://datatracker.ietf.org/doc/html/rfc4193#section-8.
            return (BIP155Network.CJDNS, addr_bytes)
        else:
            return (BIP155Network.IPV6, addr_bytes)
    else:
        raise ValueError(f'Could not parse address: {addr}')

def parse_spec(s):
    '''
    Convert an endpoint string (e.g., "192.168.1.1:8333", "[::1]:8333") to a
    BIP155 (networkID, addr_bytes, port) tuple.
    Returns None if the address type is no longer supported (e.g., TORV2).
    '''
    # Regular expression to match IPv6 addresses with optional port, e.g., "[::1]:8333".
    match = re.match(r'\[([0-9a-fA-F:]+)\](?::([0-9]+))?$', s)
    if match: # If it's an IPv6 address enclosed in square brackets.
        host = match.group(1)
        port = match.group(2)
    elif s.count(':') > 1: # If it's an IPv6 address without brackets and no port, e.g., "::1".
        host = s
        port = ''
    else: # Assume IPv4 or hostname:port format.
        (host,_,port) = s.partition(':') # Partition by the first colon.

    if not port:
        port = 0 # Default port if not specified.
    else:
        port = int(port)

    host_parsed = name_to_bip155(host)

    if host_parsed[0] == BIP155Network.TORV2:
        # TORV2 is no longer supported, so we ignore it.
        return None
    else:
        # Return the (networkID, addr_bytes, port) tuple.
        return host_parsed + (port, )

def ser_compact_size(l):
    '''
    Serialize a compact size integer (used for length prefixing in BIP155).
    '''
    r = b""
    if l < 253:
        r = l.to_bytes(1, "little")
    elif l < 0x10000:
        r = (253).to_bytes(1, "little") + l.to_bytes(2, "little")
    elif l < 0x100000000:
        r = (254).to_bytes(1, "little") + l.to_bytes(4, "little")
    else:
        r = (255).to_bytes(1, "little") + l.to_bytes(8, "little")
    return r

def bip155_serialize(spec):
    '''
    Serialize a (networkID, addr_bytes, port) tuple to BIP155 binary format.
    The format is: networkID (1 byte) + compact_size(len(addr_bytes)) + addr_bytes + port (2 bytes, big-endian).
    '''
    r = b""
    r += spec[0].value.to_bytes(1, "little") # Network ID
    r += ser_compact_size(len(spec[1]))     # Length of address bytes
    r += spec[1]                             # Address bytes
    r += spec[2].to_bytes(2, "big")          # Port
    return r

def process_nodes(output_file_handle, input_file_handle, structname):
    '''
    Reads node addresses from an input file, processes them, and writes
    the serialized binary data as a C++ array to the output file.
    '''
    output_file_handle.write(f'static const uint8_t {structname}[] = {{\n')
    for line in input_file_handle:
        # Remove comments (everything after '#').
        comment_start = line.find('#')
        if comment_start != -1:
            line = line[0:comment_start]
        line = line.strip() # Remove leading/trailing whitespace.
        if not line:
            continue # Skip empty lines.

        try:
            spec = parse_spec(line)
        except ValueError as e:
            print(f"Warning: Skipping malformed address '{line.strip()}': {e}", file=sys.stderr)
            continue

        if spec is None:
            # Ignore unsupported addresses (e.g., TORV2).
            continue

        blob = bip155_serialize(spec)
        # Format the blob bytes as a comma-separated hex string for C++ array.
        hoststr = ','.join((f'0x{b:02x}' for b in blob))
        output_file_handle.write(f'    {hoststr},\n')
    output_file_handle.write('};\n')

def main():
    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} <path_to_nodes_txt>', file=sys.stderr)
        sys.exit(1)

    output_handle = sys.stdout # Output to stdout.
    indir = sys.argv[1] # Directory containing the node files.

    output_handle.write('#ifndef BITCOIN_CHAINPARAMSSEEDS_H\n')
    output_handle.write('#define BITCOIN_CHAINPARAMSSEEDS_H\n')
    output_handle.write('/**\n')
    output_handle.write(' * List of fixed seed nodes for the bitcoin network\n')
    output_handle.write(' * AUTOGENERATED by contrib/seeds/generate-seeds.py\n')
    output_handle.write(' *\n')
    output_handle.write(' * Each line contains a BIP155 serialized (networkID, addr, port) tuple.\n')
    output_handle.write(' */\n')

    # Process nodes for main network.
    with open(os.path.join(indir,'nodes_main.txt'), 'r', encoding="utf8") as f:
        process_nodes(output_handle, f, 'chainparams_seed_main')
    output_handle.write('\n')

    # Process nodes for signet network.
    with open(os.path.join(indir,'nodes_signet.txt'), 'r', encoding="utf8") as f:
        process_nodes(output_handle, f, 'chainparams_seed_signet')
    output_handle.write('\n')

    # Process nodes for test network.
    with open(os.path.join(indir,'nodes_test.txt'), 'r', encoding="utf8") as f:
        process_nodes(output_handle, f, 'chainparams_seed_test')
    output_handle.write('\n')

    # Process nodes for testnet4 network.
    with open(os.path.join(indir,'nodes_testnet4.txt'), 'r', encoding="utf8") as f:
        process_nodes(output_handle, f, 'chainparams_seed_testnet4')
    output_handle.write('#endif // BITCOIN_CHAINPARAMSSEEDS_H\n')

if __name__ == '__main__':
    main()