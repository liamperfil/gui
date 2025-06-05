#!/usr/bin/env python3
# Copyright (c) 2020-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import argparse
import io
import requests
import subprocess
import sys
import xml.etree.ElementTree as ET # Renamed for common convention

# --- Constants ---
DEFAULT_GLOBAL_FAUCET = 'https://signetfaucet.com/claim'
DEFAULT_GLOBAL_CAPTCHA = 'https://signetfaucet.com/captcha'
GLOBAL_FIRST_BLOCK_HASH = '00000086d6b2636cb2a392d45edc4ec544a10024d30141c9adf4bfd9de533b53'

# Braille Unicode Block for image printing
BRAILLE_BASE = 0x2800
BRAILLE_BIT_PER_PIXEL = [
    [0x01, 0x08],
    [0x02, 0x10],
    [0x04, 0x20],
    [0x40, 0x80],
]
BRAILLE_BLOCK_WIDTH = 2
BRAILLE_BLOCK_HEIGHT = 4

# External command
CONVERT_CMD = 'convert' # Renamed for clarity

# --- Utility Classes and Functions ---

class PPMImage:
    '''
    Load a PPM image (Pillow-ish API).
    Supports P6 (raw RGB) format.
    '''
    def __init__(self, f):
        header = f.readline().strip()
        if header != b'P6':
            raise ValueError(f'Invalid PPM format: expected P6, got {header}')

        size_line = f.readline().strip()
        try:
            width_str, height_str = size_line.split(b' ')
            self.width = int(width_str)
            self.height = int(height_str)
        except ValueError:
            raise ValueError(f'Invalid PPM format: dimensions line "{size_line.decode()}"')

        color_depth_line = f.readline().strip()
        if color_depth_line != b'255':
            raise ValueError(f'Invalid PPM format: expected color depth 255, got {color_depth_line.decode()}')

        # Read image data
        data_len = self.width * self.height * 3
        data = f.read(data_len)
        if len(data) != data_len:
            raise ValueError('Invalid PPM format: unexpected EOF or corrupted data')

        self.size = (self.width, self.height)
        # Store pixels in a flat list for potentially better cache performance
        # Can be converted to a 2D list if direct row/col access is frequent
        self._pixels = [tuple(data[i:i+3]) for i in range(0, data_len, 3)]

    def getpixel(self, pos):
        x, y = pos
        if not (0 <= x < self.width and 0 <= y < self.height):
            raise IndexError(f'Pixel coordinate ({x}, {y}) out of bounds for image of size {self.size}')
        return self._pixels[y * self.width + x]

def print_image_as_braille(img, threshold=128):
    '''
    Prints a black-and-white image to the terminal using braille unicode characters.
    Pixels with a red component value below 'threshold' are considered "on".
    '''
    x_blocks = (img.width + BRAILLE_BLOCK_WIDTH - 1) // BRAILLE_BLOCK_WIDTH
    y_blocks = (img.height + BRAILLE_BLOCK_HEIGHT - 1) // BRAILLE_BLOCK_HEIGHT

    for yb in range(y_blocks):
        line_chars = []
        for xb in range(x_blocks):
            braille_char_code = BRAILLE_BASE
            for y_in_block in range(BRAILLE_BLOCK_HEIGHT):
                for x_in_block in range(BRAILLE_BLOCK_WIDTH):
                    x_coord = xb * BRAILLE_BLOCK_WIDTH + x_in_block
                    y_coord = yb * BRAILLE_BLOCK_HEIGHT + y_in_block

                    if x_coord < img.width and y_coord < img.height:
                        pixel = img.getpixel((x_coord, y_coord))
                        # Check red component for simplicity, assuming grayscale or BW images
                        if pixel[0] < threshold:
                            braille_char_code |= BRAILLE_BIT_PER_PIXEL[y_in_block][x_in_block]
            line_chars.append(chr(braille_char_code))
        print(''.join(line_chars))

def run_bitcoin_cli(cmd_path, cli_args, rpc_command_and_params):
    """
    Executes a bitcoin-cli command and returns its output.
    Handles FileNotFoundError and CalledProcessError.
    """
    argv = [cmd_path] + cli_args + rpc_command_and_params
    try:
        return subprocess.check_output(argv, text=True, stderr=subprocess.PIPE).strip()
    except FileNotFoundError:
        raise SystemExit(f"Error: The binary '{cmd_path}' could not be found. Please ensure it's in your PATH or specify its full path.")
    except subprocess.CalledProcessError as e:
        cmdline = ' '.join(argv)
        # Include stderr in the error message for better debugging
        raise SystemExit(f"Error while calling '{cmdline}':\n{e.stderr.strip()}\nExited with code {e.returncode}")

def get_bitcoin_address(cmd_path, cli_args):
    """Retrieves a new Bitcoin address for receiving coins."""
    try:
        return run_bitcoin_cli(cmd_path, cli_args, ['getnewaddress', 'faucet', 'bech32'])
    except SystemExit as e:
        raise SystemExit(f"Failed to get a new Bitcoin address: {e}")

# --- Main Logic ---

def main():
    parser = argparse.ArgumentParser(
        description='Script to get coins from a faucet.',
        epilog='You may need to start with double-dash (--) when providing bitcoin-cli arguments.'
    )
    parser.add_argument('-c', '--cmd', dest='cmd', default='bitcoin-cli',
                        help='bitcoin-cli command to use (default: %(default)s)')
    parser.add_argument('-f', '--faucet', dest='faucet', default=DEFAULT_GLOBAL_FAUCET,
                        help='URL of the faucet (default: %(default)s)')
    parser.add_argument('-g', '--captcha', dest='captcha', default=DEFAULT_GLOBAL_CAPTCHA,
                        help='URL of the faucet captcha, or empty if no captcha is needed (default: %(default)s)')
    parser.add_argument('-a', '--addr', dest='addr', default='',
                        help='Bitcoin address to which the faucet should send (default: auto-generated)')
    parser.add_argument('-p', '--password', dest='password', default='',
                        help='Faucet password, if any')
    parser.add_argument('-n', '--amount', dest='amount', default='0.001',
                        help='Amount to request (0.001-0.1, default: %(default)s)')
    parser.add_argument('-i', '--imagemagick', dest='imagemagick', default=CONVERT_CMD,
                        help='Path to imagemagick convert utility (default: %(default)s)')
    parser.add_argument('bitcoin_cli_args', nargs='*',
                        help='Arguments to pass on to bitcoin-cli (default: -signet)')

    args = parser.parse_args()

    if not args.bitcoin_cli_args: # Use 'not args.bitcoin_cli_args' for empty list check
        args.bitcoin_cli_args = ['-signet']

    # Determine if global faucet is being used and validate signet hash
    is_global_faucet = (args.faucet.lower() == DEFAULT_GLOBAL_FAUCET)
    if is_global_faucet:
        try:
            curr_signet_hash = run_bitcoin_cli(args.cmd, args.bitcoin_cli_args, ['getblockhash', '1'])
            if curr_signet_hash != GLOBAL_FIRST_BLOCK_HASH:
                raise SystemExit(
                    'Error: The global faucet cannot be used with a custom Signet network. '
                    'Please use the global signet or set up your custom faucet.'
                )
        except SystemExit as e:
            # Re-raise with a more specific message for getblockhash failure
            raise SystemExit(f"Could not verify signet chain for global faucet: {e}")
    elif args.captcha == DEFAULT_GLOBAL_CAPTCHA:
        # For custom faucets, don't request captcha by default if default global captcha is set
        args.captcha = ''

    if not args.addr: # Use 'not args.addr' for empty string check
        args.addr = get_bitcoin_address(args.cmd, args.bitcoin_cli_args)
        print(f"Using generated address: {args.addr}")

    request_data = {
        'address': args.addr,
        'password': args.password,
        'amount': args.amount
    }

    session = requests.Session()

    if args.captcha: # Only attempt captcha if URL is provided
        try:
            print(f"Attempting to retrieve captcha from: {args.captcha}")
            res_captcha = session.get(args.captcha, timeout=10) # Add timeout
            res_captcha.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        except requests.exceptions.RequestException as e:
            raise SystemExit(f"Error fetching captcha from {args.captcha}: {e}")

        # Validate SVG dimensions
        try:
            svg = ET.fromstring(res_captcha.content)
            width = svg.attrib.get('width')
            height = svg.attrib.get('height')
            if width != '150' or height != '50':
                raise ValueError(f"Captcha size doesn't match expected dimensions 150x50. Got {width}x{height}")
        except ET.ParseError:
            raise SystemExit("Error: Captcha response is not a valid SVG.")
        except ValueError as e:
            raise SystemExit(f"Error: {e}")

        # Convert SVG to PPM using ImageMagick
        try:
            print("Converting captcha image...")
            convert_process = subprocess.run(
                [args.imagemagick, 'svg:-', '-depth', '8', 'ppm:-'],
                input=res_captcha.content,
                check=True,
                capture_output=True
            )
            img = PPMImage(io.BytesIO(convert_process.stdout))
        except FileNotFoundError:
            raise SystemExit(
                f"Error: The binary '{args.imagemagick}' could not be found. "
                "Please make sure ImageMagick (or a compatible fork) is installed "
                "and that the correct path is specified."
            )
        except subprocess.CalledProcessError as e:
            raise SystemExit(
                f"Error converting SVG with ImageMagick: {e.stderr.decode().strip()}\n"
                f"Command: {' '.join(e.cmd)}\nExited with code {e.returncode}"
            )
        except ValueError as e: # Catch errors from PPMImage constructor
            raise SystemExit(f"Error parsing PPM image: {e}")

        # Display captcha and get user input
        print_image_as_braille(img)
        print(f"Please solve the captcha from {args.captcha}")
        request_data['captcha'] = input('Enter captcha: ').strip()
        if not request_data['captcha']:
            raise SystemExit("Captcha cannot be empty. Please enter the captcha value.")

    # Submit request to faucet
    try:
        print(f"Requesting coins from faucet: {args.faucet}")
        res_faucet = session.post(args.faucet, data=request_data, timeout=30) # Add timeout
        res_faucet.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        print("\n--- Faucet Response ---")
        print(res_faucet.text)
    except requests.exceptions.HTTPError as e:
        status_code = e.response.status_code
        print(f"\n--- Faucet Error ({status_code}) ---")
        print(e.response.text) # Print error response from faucet
        if status_code == 404:
            print('Error: The specified faucet URL does not exist. Please check for any server issues/typo.')
        elif status_code == 429:
            print('Error: The global faucet is rate-limited (1 request/IP/day). '
                  'You might need to wait or access the faucet website manually.')
        else:
            print(f'Please check the provided arguments for their validity and/or any possible typo.')
        sys.exit(1) # Exit with an error code
    except requests.exceptions.ConnectionError as e:
        raise SystemExit(f"Error: Could not connect to the faucet at {args.faucet}. Please check your internet connection or the faucet URL. Details: {e}")
    except requests.exceptions.Timeout:
        raise SystemExit(f"Error: Faucet request timed out after {30} seconds.")
    except requests.exceptions.RequestException as e:
        raise SystemExit(f"An unexpected error occurred when contacting the faucet: {e}")
    except Exception as e:
        # Catch any other unexpected errors during the POST request
        raise SystemExit(f"An unhandled error occurred during faucet interaction: {e}")

if __name__ == "__main__":
    try:
        rv = subprocess.run([args.imagemagick, 'svg:-', '-depth', '8', 'ppm:-'], input=res.content, check=True, capture_output=True)
    except FileNotFoundError:
        raise SystemExit(f"The binary {args.imagemagick} could not be found. Please make sure ImageMagick (or a compatible fork) is installed and that the correct path is specified.")

    img = PPMImage(io.BytesIO(rv.stdout))

    # Terminal interaction
    print_image(img)
    print(f"Captcha from URL {args.captcha}")
    data['captcha'] = input('Enter captcha: ')

try:
    res = session.post(args.faucet, data=data)
except Exception:
    raise SystemExit(f"Unexpected error when contacting faucet: {sys.exc_info()[0]}")

# Display the output as per the returned status code
if res:
    # When the return code is in between 200 and 400 i.e. successful
    print(res.text)
elif res.status_code == 404:
    print('The specified faucet URL does not exist. Please check for any server issues/typo.')
elif res.status_code == 429:
    print('The script does not allow for repeated transactions as the global faucet is rate-limited to 1 request/IP/day. You can access the faucet website to get more coins manually')
else:
    print(f'Returned Error Code {res.status_code}\n{res.text}\n')
    print('Please check the provided arguments for their validity and/or any possible typo.')
