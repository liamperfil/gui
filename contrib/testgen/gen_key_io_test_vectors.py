#!/usr/bin/env python3
# Copyright (c) 2012-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
'''
Generate valid and invalid base58/bech32(m) address and private key test vectors.
'''

from itertools import islice
import os
import random
import sys
from typing import Dict, Any, Tuple, List, Union

sys.path.append(os.path.join(os.path.dirname(__file__), '../../test/functional'))

from test_framework.address import base58_to_byte, byte_to_base58, b58chars  # noqa: E402
from test_framework.script import OP_0, OP_1, OP_2, OP_3, OP_16, OP_DUP, OP_EQUAL, OP_EQUALVERIFY, OP_HASH160, OP_CHECKSIG  # noqa: E402
from test_framework.segwit_addr import bech32_encode, decode_segwit_address, convertbits, CHARSET, Encoding  # noqa: E402

# Key types for base58 addresses
PUBKEY_ADDRESS = 0
SCRIPT_ADDRESS = 5
PUBKEY_ADDRESS_TEST = 111
SCRIPT_ADDRESS_TEST = 196
PUBKEY_ADDRESS_REGTEST = 111
SCRIPT_ADDRESS_REGTEST = 196
PRIVKEY = 128
PRIVKEY_TEST = 239
PRIVKEY_REGTEST = 239

# Script prefixes and suffixes for various address types
pubkey_prefix = (OP_DUP, OP_HASH160, 20)
pubkey_suffix = (OP_EQUALVERIFY, OP_CHECKSIG)
script_prefix = (OP_HASH160, 20)
script_suffix = (OP_EQUAL,)
p2wpkh_prefix = (OP_0, 20)
p2wsh_prefix = (OP_0, 32)
p2tr_prefix = (OP_1, 32)

metadata_keys = ['isPrivkey', 'chain', 'isCompressed', 'tryCaseFlip']

# Templates for valid base58 sequences:
# (prefix_bytes, payload_size, suffix_bytes, metadata_tuple, output_prefix_bytes, output_suffix_bytes)
# metadata_tuple: (isPrivkey: bool, chain: str, isCompressed: bool|None, tryCaseFlip: bool|None)
templates: List[Tuple[Tuple[int, ...], int, Tuple[int, ...], Tuple[Union[bool, str, None], ...], Tuple[int, ...], Tuple[int, ...]]] = [
    ((PUBKEY_ADDRESS,),         20, (),   (False, 'main',    None, None), pubkey_prefix, pubkey_suffix),
    ((SCRIPT_ADDRESS,),         20, (),   (False, 'main',    None, None), script_prefix, script_suffix),
    ((PUBKEY_ADDRESS_TEST,),    20, (),   (False, 'test',    None, None), pubkey_prefix, pubkey_suffix),
    ((SCRIPT_ADDRESS_TEST,),    20, (),   (False, 'test',    None, None), script_prefix, script_suffix),
    ((PUBKEY_ADDRESS_TEST,),    20, (),   (False, 'signet',  None, None), pubkey_prefix, pubkey_suffix),
    ((SCRIPT_ADDRESS_TEST,),    20, (),   (False, 'signet',  None, None), script_prefix, script_suffix),
    ((PUBKEY_ADDRESS_REGTEST,), 20, (),   (False, 'regtest', None, None), pubkey_prefix, pubkey_suffix),
    ((SCRIPT_ADDRESS_REGTEST,), 20, (),   (False, 'regtest', None, None), script_prefix, script_suffix),
    ((PRIVKEY,),                32, (),   (True,  'main',    False, None), (),            ()),
    ((PRIVKEY,),                32, (1,), (True,  'main',    True,  None), (),            ()),
    ((PRIVKEY_TEST,),           32, (),   (True,  'test',    False, None), (),            ()),
    ((PRIVKEY_TEST,),           32, (1,), (True,  'test',    True,  None), (),            ()),
    ((PRIVKEY_TEST,),           32, (),   (True,  'signet',  False, None), (),            ()),
    ((PRIVKEY_TEST,),           32, (1,), (True,  'signet',  True,  None), (),            ()),
    ((PRIVKEY_REGTEST,),        32, (),   (True,  'regtest', False, None), (),            ()),
    ((PRIVKEY_REGTEST,),        32, (1,), (True,  'regtest', True,  None), (),            ())
]

# Templates for valid bech32 sequences:
# (hrp, version, witprog_size, metadata_tuple, encoding, output_prefix_bytes)
bech32_templates: List[Tuple[str, int, int, Tuple[Union[bool, str, None], ...], Encoding, Tuple[int, ...]]] = [
    ('bc',      0, 20, (False, 'main',    None, True), Encoding.BECH32,   p2wpkh_prefix),
    ('bc',      0, 32, (False, 'main',    None, True), Encoding.BECH32,   p2wsh_prefix),
    ('bc',      1, 32, (False, 'main',    None, True), Encoding.BECH32M,  p2tr_prefix),
    ('bc',      2,  2, (False, 'main',    None, True), Encoding.BECH32M,  (OP_2, 2)),
    ('tb',      0, 20, (False, 'test',    None, True), Encoding.BECH32,   p2wpkh_prefix),
    ('tb',      0, 32, (False, 'test',    None, True), Encoding.BECH32,   p2wsh_prefix),
    ('tb',      1, 32, (False, 'test',    None, True), Encoding.BECH32M,  p2tr_prefix),
    ('tb',      3, 16, (False, 'test',    None, True), Encoding.BECH32M,  (OP_3, 16)),
    ('tb',      0, 20, (False, 'signet',  None, True), Encoding.BECH32,   p2wpkh_prefix),
    ('tb',      0, 32, (False, 'signet',  None, True), Encoding.BECH32,   p2wsh_prefix),
    ('tb',      1, 32, (False, 'signet',  None, True), Encoding.BECH32M,  p2tr_prefix),
    ('tb',      3, 32, (False, 'signet',  None, True), Encoding.BECH32M,  (OP_3, 32)),
    ('bcrt',    0, 20, (False, 'regtest', None, True), Encoding.BECH32,   p2wpkh_prefix),
    ('bcrt',    0, 32, (False, 'regtest', None, True), Encoding.BECH32,   p2wsh_prefix),
    ('bcrt',    1, 32, (False, 'regtest', None, True), Encoding.BECH32M,  p2tr_prefix),
    ('bcrt',   16, 40, (False, 'regtest', None, True), Encoding.BECH32M,  (OP_16, 40))
]

# Templates for invalid bech32 sequences:
# (hrp, version, witprog_size, encoding, invalid_bech32_data_length, invalid_checksum, invalid_char)
bech32_ng_templates: List[Tuple[str, int, int, Encoding, bool, bool, bool]] = [
    ('tc',      0, 20, Encoding.BECH32,   False, False, False),
    ('bt',      1, 32, Encoding.BECH32M,  False, False, False),
    ('tb',     17, 32, Encoding.BECH32M,  False, False, False),
    ('bcrt',    3,  1, Encoding.BECH32M,  False, False, False),
    ('bc',     15, 41, Encoding.BECH32M,  False, False, False),
    ('tb',      0, 16, Encoding.BECH32,   False, False, False),
    ('bcrt',    0, 32, Encoding.BECH32,   True,  False, False),
    ('bc',      0, 16, Encoding.BECH32,   True,  False, False),
    ('tb',      0, 32, Encoding.BECH32,   False, True,  False),
    ('bcrt',    0, 20, Encoding.BECH32,   False, False, True),
    ('bc',      0, 20, Encoding.BECH32M,  False, False, False),
    ('tb',      0, 32, Encoding.BECH32M,  False, False, False),
    ('bcrt',    0, 20, Encoding.BECH32M,  False, False, False),
    ('bc',      1, 32, Encoding.BECH32,   False, False, False),
    ('tb',      2, 16, Encoding.BECH32,   False, False, False),
    ('bcrt',   16, 20, Encoding.BECH32,   False, False, False),
]

def is_valid_base58(v: str) -> bool:
    """
    Check if a given string is a valid base58 address or private key.

    Args:
        v: The string to validate.

    Returns:
        True if valid, False otherwise.
    """
    # Check for non-base58 characters first to quickly disqualify
    if len(set(v) - set(b58chars)) > 0:
        return False
    try:
        payload_bytes, version = base58_to_byte(v)
        result = bytes([version]) + payload_bytes
    except ValueError:  # thrown if checksum doesn't match or other base58 decoding issue
        return False

    for template in templates:
        prefix = bytearray(template[0])
        payload_size = template[1]
        suffix = bytearray(template[2])
        if result.startswith(prefix) and result.endswith(suffix):
            if (len(result) - len(prefix) - len(suffix)) == payload_size:
                return True
    return False

def is_valid_bech32(v: str) -> bool:
    """
    Check if a given string is a valid bech32 address.

    Args:
        v: The string to validate.

    Returns:
        True if valid, False otherwise.
    """
    for hrp in ['bc', 'tb', 'bcrt']:
        if decode_segwit_address(hrp, v) != (None, None):
            return True
    return False

def is_valid(v: str) -> bool:
    """
    Check if a given string is a valid base58 or bech32 address/private key.

    Args:
        v: The string to validate.

    Returns:
        True if valid, False otherwise.
    """
    return is_valid_base58(v) or is_valid_bech32(v)

def gen_valid_base58_vector(template: Tuple[Tuple[int, ...], int, Tuple[int, ...], Tuple[Union[bool, str, None], ...], Tuple[int, ...], Tuple[int, ...]]) -> Tuple[str, bytearray]:
    """
    Generate a valid base58 test vector.

    Args:
        template: A tuple containing generation parameters:
                  (prefix_bytes, payload_size, suffix_bytes, metadata_tuple,
                   output_prefix_bytes, output_suffix_bytes)

    Returns:
        A tuple containing:
        - The generated base58 string.
        - The expected decoded payload as a bytearray.
    """
    prefix = bytearray(template[0])
    payload = rand_bytes(size=template[1])
    suffix = bytearray(template[2])
    dst_prefix = bytearray(template[4])
    dst_suffix = bytearray(template[5])
    assert len(prefix) == 1
    rv = byte_to_base58(payload + suffix, prefix[0])
    return rv, dst_prefix + payload + dst_suffix

def gen_valid_bech32_vector(template: Tuple[str, int, int, Tuple[Union[bool, str, None], ...], Encoding, Tuple[int, ...]]) -> Tuple[str, bytearray]:
    """
    Generate a valid bech32 test vector.

    Args:
        template: A tuple containing generation parameters:
                  (hrp, version, witprog_size, metadata_tuple, encoding, output_prefix_bytes)

    Returns:
        A tuple containing:
        - The generated bech32 string.
        - The expected decoded witness program as a bytearray.
    """
    hrp = template[0]
    witver = template[1]
    witprog = rand_bytes(size=template[2])
    encoding = template[4]
    dst_prefix = bytearray(template[5])
    rv = bech32_encode(encoding, hrp, [witver] + convertbits(witprog, 8, 5))
    return rv, dst_prefix + witprog

def gen_valid_vectors():
    """
    Generate valid test vectors for base58 and bech32.

    Yields:
        A tuple containing:
        - The generated valid string.
        - The hexadecimal representation of the expected decoded payload.
        - A dictionary of metadata associated with the vector.
    """
    glist = [gen_valid_base58_vector, gen_valid_bech32_vector]
    tlist = [templates, bech32_templates]
    while True:
        for template_list, valid_vector_generator_func in zip(glist, tlist):
            for template in template_list:
                # template_list is actually the generator function, template is the actual template data
                rv, payload = valid_vector_generator_func(template)
                assert is_valid(rv)
                metadata = {key: value for key, value in zip(metadata_keys, template[3]) if value is not None}
                hexrepr = payload.hex()
                yield (rv, hexrepr, metadata)

def gen_invalid_base58_vector(template: Tuple[Tuple[int, ...], int, Tuple[int, ...], Tuple[Union[bool, str, None], ...], Tuple[int, ...], Tuple[int, ...]]) -> str:
    """
    Generate a possibly invalid base58 test vector.

    Args:
        template: A tuple containing generation parameters, similar to valid templates.

    Returns:
        The generated invalid base58 string.
    """
    corrupt_prefix = randbool(0.2)
    randomize_payload_size = randbool(0.2)
    corrupt_suffix = randbool(0.2)

    if corrupt_prefix:
        prefix = rand_bytes(size=1)
    else:
        prefix = bytearray(template[0])

    if randomize_payload_size:
        payload = rand_bytes(size=max(int(random.expovariate(0.5)), 50))
    else:
        payload = rand_bytes(size=template[1])

    if corrupt_suffix:
        suffix = rand_bytes(size=len(template[2]))
    else:
        suffix = bytearray(template[2])

    assert len(prefix) == 1
    val = byte_to_base58(payload + suffix, prefix[0])

    # Introduce line corruption (add/replace random character)
    if random.randint(0, 10) < 1:
        if randbool():  # add random character to end
            val += random.choice(b58chars)
        else:  # replace random character in the middle
            n = random.randint(0, len(val) - 1) if val else 0 # Ensure n is valid index
            if val: # Only perform replacement if string is not empty
                val = val[0:n] + random.choice(b58chars) + val[n + 1:]

    return val

def gen_invalid_bech32_vector(template: Tuple[str, int, int, Encoding, bool, bool, bool]) -> str:
    """
    Generate a possibly invalid bech32 test vector.

    Args:
        template: A tuple containing generation parameters:
                  (hrp, version, witprog_size, encoding, invalid_bech32_data_length,
                   invalid_checksum, invalid_char_corruption)

    Returns:
        The generated invalid bech32 string.
    """
    no_data = randbool(0.1)
    to_upper = randbool(0.1)
    hrp = template[0]
    witver = template[1]
    witprog = rand_bytes(size=template[2])
    encoding = template[3]

    if no_data:
        rv = bech32_encode(encoding, hrp, [])
    else:
        data = [witver] + convertbits(witprog, 8, 5)
        # Apply invalid_bech32_data_length corruption if specified
        if template[4] and not no_data:
            if template[2] % 5 in {2, 4}:
                data[-1] |= 1  # Corrupt last bit if witprog_size makes it non-byte aligned
            else:
                data.append(0)  # Add extra data if witprog_size is byte aligned
        rv = bech32_encode(encoding, hrp, data)

    # Apply invalid_checksum corruption
    if template[5]:
        if rv: # Ensure rv is not empty before attempting modification
            i = len(rv) - random.randrange(1, 7) # Corrupt a character near the end (checksum part)
            rv = rv[:i] + random.choice(CHARSET.replace(rv[i], '')) + rv[i + 1:]

    # Apply invalid_char_corruption (case flip within data or hrp)
    if template[6]:
        if rv and len(rv) > len(hrp) + 4: # Ensure string is long enough for modification
            i = len(hrp) + 1 + random.randrange(0, len(rv) - len(hrp) - 4)
            rv = rv[:i] + rv[i:i + 4].upper() + rv[i + 4:]

    # Apply overall case flip if specified
    if to_upper:
        rv = rv.swapcase()

    return rv

def randbool(p: float = 0.5) -> bool:
    """
    Return True with probability P(p).

    Args:
        p: Probability of returning True (0.0 to 1.0).

    Returns:
        True or False.
    """
    return random.random() < p

def rand_bytes(*, size: int) -> bytearray:
    """
    Generate a bytearray of random bytes.

    Args:
        size: The number of random bytes to generate.

    Returns:
        A bytearray containing random bytes.
    """
    return bytearray(random.getrandbits(8) for _ in range(size))

def gen_invalid_vectors():
    """
    Generate invalid test vectors for base58 and bech32.

    Yields:
        A tuple containing the generated invalid string.
    """
    # Start with some manual edge-cases
    yield "",
    yield "x",

    glist = [gen_invalid_base58_vector, gen_invalid_bech32_vector]
    tlist = [templates, bech32_ng_templates] # Note: 'templates' used for base58, 'bech32_ng_templates' for bech32

    while True:
        # Iterate through both base58 and bech32 invalid vector generators
        for template_set, invalid_vector_generator_func in zip(glist, tlist):
            for template_data in template_set:
                # template_set is actually the generator function, template_data is the actual template
                val = invalid_vector_generator_func(template_data)
                if not is_valid(val):
                    yield val,

def main():
    """
    Main function to generate and print test vectors.
    """
    import json
    iters = {'valid': gen_valid_vectors, 'invalid': gen_invalid_vectors}
    random.seed(42) # Ensure reproducibility of test vectors

    try:
        # Determine which iterator to use based on command line argument
        uiter = iters[sys.argv[1]]
    except (IndexError, KeyError):
        # Default to valid vectors if no argument or invalid argument provided
        uiter = gen_valid_vectors

    try:
        # Determine how many vectors to generate
        count = int(sys.argv[2])
    except (IndexError, ValueError):
        # Default to 0 (meaning infinite for `islice` without a stop)
        count = 0

    # Generate the vectors and dump them to stdout as JSON
    data = list(islice(uiter(), count))
    json.dump(data, sys.stdout, sort_keys=True, indent=4)
    sys.stdout.write('\n')

if __name__ == '__main__':
    main()