#!/usr/bin/env python3
# Copyright (c) 2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Demonstration of eBPF limitations and the effect on USDT with the
net:inbound_message and net:outbound_message tracepoints from Bitcoin Core.

This script uses BCC (https://github.com/iovisor/bcc) to load a sandboxed
eBPF program into the Linux kernel (root privileges are required). The eBPF
program attaches to two statically defined tracepoints:
'net:inbound_message' (for received P2P messages) and
'net:outbound_message' (for sent P2P messages).
The P2P messages are submitted to this script via a BPF ring buffer
and are then printed.

eBPF Limitations Demonstrated:
* **Message Size**: Bitcoin P2P messages can be larger than 32kb.
    The eBPF VM's stack is limited to 512 bytes, and the maximum allocation for a
    P2P message in eBPF is about 32kb. Larger messages are truncated
    at MAX_MSG_DATA_LENGTH. The script detects and warns about truncated messages.
* **Buffer Throughput**: The ring buffer has limited throughput. Messages
    submitted in rapid succession can fill the ring buffer faster than it can be read,
    resulting in some messages being lost. BCC may report "Possibly lost
    N samples" in these cases.
"""

import sys
import argparse # Import for more flexible command-line argument handling
from bcc import BPF, USDT
import os # To check for PID existence

# BCC: The C program to be compiled to an eBPF program (by BCC) and loaded into
# a sandboxed Linux kernel VM.
# This eBPF program will intercept and process P2P messages.
program = """
#include <uapi/linux/ptrace.h>

// A min() macro. Prefixed with _TRACEPOINT_TEST to avoid collision with other MIN macros.
#define _TRACEPOINT_TEST_MIN(a,b) ({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a < _b ? _a : _b; })

// Maximum possible allocation size, from include/linux/percpu.h in the Linux kernel.
#define PCPU_MIN_UNIT_SIZE (32 << 10) // 32KB

// Maximum length definitions for strings, based on Tor v3 address specifications.
#define MAX_PEER_ADDR_LENGTH 62 + 6 // Tor v3 addresses (62 chars) + port (6 chars)
#define MAX_PEER_CONN_TYPE_LENGTH 20 // Connection type (e.g., "outbound-full-relay")
#define MAX_MSG_TYPE_LENGTH 20     // P2P message type (e.g., "version", "block", "tx")

// The maximum message data length is the PCPU_MIN_UNIT_SIZE minus an offset.
// This offset ensures the entire struct fits within the maximum eBPF allocation.
#define MAX_MSG_DATA_LENGTH PCPU_MIN_UNIT_SIZE - 200

// Structure to store P2P message data.
// This structure is used to pass data from the kernel (eBPF) to user-space (Python).
struct p2p_message
{
    u64     peer_id;                // Unique ID of the peer
    char    peer_addr[MAX_PEER_ADDR_LENGTH];        // Peer's address
    char    peer_conn_type[MAX_PEER_CONN_TYPE_LENGTH]; // Type of connection with the peer
    char    msg_type[MAX_MSG_TYPE_LENGTH];          // P2P message type (e.g., "version", "block")
    u64     msg_size;               // Total size of the P2P message (can be larger than MAX_MSG_DATA_LENGTH)
    u8      msg[MAX_MSG_DATA_LENGTH];             // P2P message data (truncated if larger than MAX_MSG_DATA_LENGTH)
};

// We cannot store the p2p_message struct on the eBPF stack, as it is limited to 512 bytes.
// However, we can use a BPF-array with a length of 1 to allocate up to 32768 bytes
// (defined by PCPU_MIN_UNIT_SIZE in the Linux kernel).
// See https://github.com/iovisor/bcc/issues/2306 for more details on this limitation.
BPF_ARRAY(msg_arr, struct p2p_message, 1);

// Two BPF perf buffers for pushing data (P2P messages) to user-space.
BPF_PERF_OUTPUT(inbound_messages);  // For received messages
BPF_PERF_OUTPUT(outbound_messages); // For sent messages

// Tracepoint function for inbound (received) P2P messages.
// It is invoked when the 'net:inbound_message' tracepoint is triggered.
int trace_inbound_message(struct pt_regs *ctx) {
    int idx = 0;
    // Attempt to get a reference to the p2p_message structure from the BPF array.
    // The array has size 1, so we always use index 0.
    struct p2p_message *msg = msg_arr.lookup(&idx);
    // Pointers to the USDT function arguments coming from user-space.
    void *paddr = NULL, *pconn_type = NULL, *pmsg_type = NULL, *pmsg = NULL;

    // The BPF verifier requires an explicit check that the `msg` pointer is not NULL,
    // even though `lookup()` will not return NULL in this context.
    // See https://github.com/iovisor/bcc/issues/2595.
    if (msg == NULL) return 1;

    // Read arguments passed by the USDT tracepoint into the p2p_message structure.
    // bpf_usdt_readarg reads a numbered argument (1-6) from the tracepoint context.
    bpf_usdt_readarg(1, ctx, &msg->peer_id);
    bpf_usdt_readarg(2, ctx, &paddr);
    // Read the string from user-space to the kernel buffer, ensuring it doesn't exceed the size.
    bpf_probe_read_user_str(&msg->peer_addr, sizeof(msg->peer_addr), paddr);
    bpf_usdt_readarg(3, ctx, &pconn_type);
    bpf_probe_read_user_str(&msg->peer_conn_type, sizeof(msg->peer_conn_type), pconn_type);
    bpf_usdt_readarg(4, ctx, &pmsg_type);
    bpf_probe_read_user_str(&msg->msg_type, sizeof(msg->msg_type), pmsg_type);
    bpf_usdt_readarg(5, ctx, &msg->msg_size);
    bpf_usdt_readarg(6, ctx, &pmsg);
    // Read message data. _TRACEPOINT_TEST_MIN ensures we don't read more than the buffer allows,
    // or more than the actual message size, whichever is smaller.
    bpf_probe_read_user(&msg->msg, _TRACEPOINT_TEST_MIN(msg->msg_size, MAX_MSG_DATA_LENGTH), pmsg);

    // Submit the filled p2p_message structure to user-space via the perf buffer.
    inbound_messages.perf_submit(ctx, msg, sizeof(*msg));
    return 0; // Success
};

// Tracepoint function for outbound (sent) P2P messages.
// It is invoked when the 'net:outbound_message' tracepoint is triggered.
int trace_outbound_message(struct pt_regs *ctx) {
    int idx = 0;
    struct p2p_message *msg = msg_arr.lookup(&idx);

    void *paddr = NULL, *pconn_type = NULL, *pmsg_type = NULL, *pmsg = NULL;

    if (msg == NULL) return 1;

    bpf_usdt_readarg(1, ctx, &msg->peer_id);
    bpf_usdt_readarg(2, ctx, &paddr);
    bpf_probe_read_user_str(&msg->peer_addr, sizeof(msg->peer_addr), paddr);
    bpf_usdt_readarg(3, ctx, &pconn_type);
    bpf_probe_read_user_str(&msg->peer_conn_type, sizeof(msg->peer_conn_type), pconn_type);
    bpf_usdt_readarg(4, ctx, &pmsg_type);
    bpf_probe_read_user_str(&msg->msg_type, sizeof(msg->msg_type), pmsg_type);
    bpf_usdt_readarg(5, ctx, &msg->msg_size);
    bpf_usdt_readarg(6, ctx, &pmsg);
    bpf_probe_read_user(&msg->msg, _TRACEPOINT_TEST_MIN(msg->msg_size, MAX_MSG_DATA_LENGTH), pmsg);

    outbound_messages.perf_submit(ctx, msg, sizeof(*msg));
    return 0; // Success
};
"""


# Function to print P2P message details.
# This function has been enhanced for clearer and more detailed output.
def print_message(event, inbound):
    """
    Prints the details of a P2P message.

    Args:
        event (object): The event object containing P2P message data
                        (mapped from the eBPF p2p_message struct).
        inbound (bool): True if the message is inbound (received), False if outbound (sent).
    """
    direction = "INBOUND" if inbound else "OUTBOUND"
    peer_id = event.peer_id
    peer_conn_type = event.peer_conn_type.decode("utf-8").strip('\x00') # Remove null bytes
    peer_addr = event.peer_addr.decode("utf-8").strip('\x00')       # Remove null bytes
    msg_type = event.msg_type.decode("utf-8").strip('\x00')         # Remove null bytes
    msg_size_total = event.msg_size
    msg_data_len_captured = len(event.msg)
    msg_data_hex = bytes(event.msg[:msg_size_total]).hex() # Ensure only up to actual message size is taken

    warning_str = ""
    if msg_data_len_captured < msg_size_total:
        warning_str = f"WARNING: Message truncated! Captured {msg_data_len_captured} of {msg_size_total} bytes. "

    print(f"[{direction}] {warning_str}Message '{msg_type}' (Total: {msg_size_total} bytes)")
    print(f"  Peer ID: {peer_id}")
    print(f"  Connection: {peer_conn_type} ({peer_addr})")
    print(f"  Data (hex): {msg_data_hex}")
    print("-" * 80) # Separator for better readability


# Main function to set up and run eBPF monitoring.
def main():
    # Set up argument parser to handle PID or process name.
    parser = argparse.ArgumentParser(
        description="Monitors Bitcoin Core P2P messages using eBPF and BCC.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("pid", nargs='?', type=int,
                        help="PID of the bitcoind process.")
    parser.add_argument("-n", "--name", type=str,
                        help="Name of the bitcoind process (e.g., 'bitcoind'). "
                             "Will be used to find the PID automatically.")
    args = parser.parse_args()

    target_pid = None

    if args.pid:
        target_pid = args.pid
    elif args.name:
        print(f"Searching for PID of process '{args.name}'...")
        try:
            # Command to find the PID of a process by name.
            # May need adjustment for different systems/environments.
            # This is a simple example that might require more robustness.
            output = os.popen(f"pgrep {args.name}").read().strip()
            if output:
                target_pid = int(output.split('\\n')[0]) # Get the first PID found
            else:
                print(f"Error: Process '{args.name}' not found.")
                sys.exit(1)
        except ValueError:
            print(f"Error: Could not get PID for '{args.name}'.")
            sys.exit(1)
        except Exception as e:
            print(f"An error occurred while searching for the PID: {e}")
            sys.exit(1)
    else:
        print("Error: You must provide either the PID or the name of the bitcoind process.")
        parser.print_help()
        sys.exit(1)

    if not os.path.exists(f"/proc/{target_pid}"):
        print(f"Error: PID {target_pid} does not correspond to a running process.")
        sys.exit(1)

    print(f"Hooking into bitcoind with pid {target_pid}")
    try:
        # Initialize the USDT object for the bitcoind PID.
        bitcoind_with_usdts = USDT(pid=target_pid)
    except Exception as e:
        print(f"Error initializing USDT for PID {target_pid}. Ensure bitcoind is running "
              "and compiled with USDT support (e.g., --enable-usdt).")
        print(f"Error details: {e}")
        sys.exit(1)

    # Attach the tracing functions defined in the BPF program to the USDT tracepoints.
    try:
        bitcoind_with_usdts.enable_probe(
            probe="inbound_message", fn_name="trace_inbound_message")
        bitcoind_with_usdts.enable_probe(
            probe="outbound_message", fn_name="trace_outbound_message")
    except Exception as e:
        print(f"Error enabling USDT probes. Check if tracepoints exist "
              "in your bitcoind build and if you have correct permissions (root).")
        print(f"Error details: {e}")
        sys.exit(1)

    # Load the eBPF program into the kernel.
    try:
        bpf = BPF(text=program, usdt_contexts=[bitcoind_with_usdts])
    except Exception as e:
        print(f"Error loading the eBPF program. Check if BCC is installed correctly "
              "and if you have root permissions.")
        print(f"Error details: {e}")
        sys.exit(1)

    # BCC: Handler function for inbound_messages.
    def handle_inbound(_, data, size):
        """ Handler for inbound messages.
        Called each time a message is submitted to the `inbound_messages` BPF table.
        """
        try:
            event = bpf["inbound_messages"].event(data)
            print_message(event, True)
        except Exception as e:
            print(f"Error processing inbound message: {e}")

    # BCC: Handler function for outbound_messages.
    def handle_outbound(_, data, size):
        """ Handler for outbound messages.
        Called each time a message is submitted to the `outbound_messages` BPF table.
        """
        try:
            event = bpf["outbound_messages"].event(data)
            print_message(event, False)
        except Exception as e:
            print(f"Error processing outbound message: {e}")

    # BCC: Add handlers to the inbound and outbound perf buffers.
    bpf["inbound_messages"].open_perf_buffer(handle_inbound)
    bpf["outbound_messages"].open_perf_buffer(handle_outbound)

    print("\n" + "="*80)
    print("Starting raw P2P message logging for Bitcoin Core.")
    print("WARNING: Messages larger than ~32KB will be TRUNCATED!")
    print("WARNING: Some messages might be LOST due to buffer throughput.")
    print("Press Ctrl+C to stop.")
    print("="*80 + "\n")

    # Main loop for polling the performance buffer.
    while True:
        try:
            bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            print("\nMonitoring stopped by user.")
            sys.exit(0)
        except Exception as e:
            print(f"Unexpected error during buffer polling: {e}")
            break # Exit the loop in case of a critical error.


if __name__ == "__main__":
    main()