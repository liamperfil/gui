#!/usr/bin/env python3
# Copyright (c) 2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Interactive Bitcoin Core P2P network traffic monitor utilizing USDT and the
net:inbound_message and net:outbound_message tracepoints.

USAGE: ./contrib/tracing/p2p_monitor.py <PID_OF_BITCOIND> [--no-curses]
"""

import argparse
import ctypes
import os
import sys
from collections import deque
from datetime import datetime, timezone

# Optional: curses for interactive TUI, if available
try:
    import curses
    from curses import panel
except ImportError:
    curses = None
    print("Warning: 'curses' module not found. Running in non-interactive mode. "
          "Install with 'pip install windows-curses' on Windows or 'pip install curses' "
          "on Linux if you want interactive TUI.")

from bcc import BPF, USDT

# Constants for BPF program and event data structures
HASH_LENGTH = 32
MAX_ADDR_LENGTH = 68  # Tor v3 addresses are 62 chars + 6 for port (':12345')
MAX_MSG_TYPE_LENGTH = 12

# BPF C program for tracing P2P messages
BPF_PROGRAM = f"""
#include <uapi/linux/ptrace.h>

#define MAX_ADDR_LENGTH {MAX_ADDR_LENGTH}
#define MAX_MSG_TYPE_LENGTH {MAX_MSG_TYPE_LENGTH}
#define HASH_LENGTH {HASH_LENGTH}

// Structure for an inbound message event
struct inbound_event
{{
  u64 timestamp_ns;
  u64 peer_id;
  u32 message_size;
  char addr[MAX_ADDR_LENGTH + 1];
  char message_type[MAX_MSG_TYPE_LENGTH + 1];
}};

// Structure for an outbound message event
struct outbound_event
{{
  u64 timestamp_ns;
  u64 peer_id;
  u32 message_size;
  char addr[MAX_ADDR_LENGTH + 1];
  char message_type[MAX_MSG_TYPE_LENGTH + 1];
}};

// BPF perf buffers to push event data to user space
BPF_PERF_OUTPUT(inbound_messages);
BPF_PERF_OUTPUT(outbound_messages);

// Tracepoint for inbound messages
int trace_inbound_message(struct pt_regs *ctx) {{
  struct inbound_event event = {{}};
  event.timestamp_ns = bpf_ktime_get_ns();
  bpf_usdt_readarg(1, ctx, &event.peer_id);
  bpf_usdt_readarg(2, ctx, &event.message_size);
  bpf_usdt_readarg(3, ctx, &event.addr);
  bpf_usdt_readarg(4, ctx, &event.message_type);
  inbound_messages.perf_submit(ctx, &event, sizeof(event));
  return 0;
}}

// Tracepoint for outbound messages
int trace_outbound_message(struct pt_regs *ctx) {{
  struct outbound_event event = {{}};
  event.timestamp_ns = bpf_ktime_get_ns();
  bpf_usdt_readarg(1, ctx, &event.peer_id);
  bpf_usdt_readarg(2, ctx, &event.message_size);
  bpf_usdt_readarg(3, ctx, &event.addr);
  bpf_usdt_readarg(4, ctx, &event.message_type);
  outbound_messages.perf_submit(ctx, &event, sizeof(event));
  return 0;
}}
"""

class InboundEvent(ctypes.Structure):
    """Corresponds to 'struct inbound_event' in BPF_PROGRAM."""
    _fields_ = [
        ("timestamp_ns", ctypes.c_uint64),
        ("peer_id", ctypes.c_uint64),
        ("message_size", ctypes.c_uint32),
        ("addr", ctypes.c_char * (MAX_ADDR_LENGTH + 1)),
        ("message_type", ctypes.c_char * (MAX_MSG_TYPE_LENGTH + 1)),
    ]

class OutboundEvent(ctypes.Structure):
    """Corresponds to 'struct outbound_event' in BPF_PROGRAM."""
    _fields_ = [
        ("timestamp_ns", ctypes.c_uint64),
        ("peer_id", ctypes.c_uint64),
        ("message_size", ctypes.c_uint32),
        ("addr", ctypes.c_char * (MAX_ADDR_LENGTH + 1)),
        ("message_type", ctypes.c_char * (MAX_MSG_TYPE_LENGTH + 1)),
    ]

class PeerMessage:
    """Represents a P2P message, either inbound or outbound."""
    def __init__(self, timestamp_ns: int, msg_type: str, size: int, inbound: bool):
        self.timestamp_ns = timestamp_ns
        self.msg_type = msg_type
        self.size = size
        self.inbound = inbound

class Peer:
    """Represents a connected peer and its recent message history."""
    def __init__(self, peer_id: int, address: str, connection_type: str):
        self.id = peer_id
        self.address = address
        self.connection_type = connection_type
        self.last_messages: deque[PeerMessage] = deque(maxlen=10) # Store last 10 messages

    def add_message(self, timestamp_ns: int, msg_type: str, size: int, inbound: bool):
        self.last_messages.append(PeerMessage(timestamp_ns, msg_type, size, inbound))

class P2PMonitor:
    """
    Monitors Bitcoin Core P2P network traffic and displays it.
    Supports interactive TUI with curses or plain stdout.
    """
    def __init__(self, pid: int, use_curses: bool):
        self.pid = pid
        self.use_curses = use_curses
        self.peers: dict[int, Peer] = {}
        self.selected_peer_id: int | None = None
        self.max_lines = 0
        self.scroll = 0

        self.stdscr = None
        self.peer_list_window = None
        self.info_window = None
        self.status_window = None

        print(f"Hooking into bitcoind with pid {self.pid}")

        try:
            self.bitcoind_with_usdts = USDT(pid=self.pid)
            self.bitcoind_with_usdts.enable_probe(
                probe="inbound_message", fn_name="trace_inbound_message")
            self.bitcoind_with_usdts.enable_probe(
                probe="outbound_message", fn_name="trace_outbound_message")

            self.bpf_instance = BPF(text=BPF_PROGRAM, usdt_contexts=[self.bitcoind_with_usdts])

            self.bpf_instance["inbound_messages"].open_perf_buffer(self._handle_inbound_event)
            self.bpf_instance["outbound_messages"].open_perf_buffer(self._handle_outbound_event)

        except Exception as e:
            print(f"Error initializing BPF: {e}", file=sys.stderr)
            print("Ensure bitcoind is running and you have sufficient permissions (e.g., sudo).", file=sys.stderr)
            sys.exit(1)

    def _get_decoded_string(self, c_char_array) -> str:
        """Decodes a C char array to a Python string, handling null terminators and errors."""
        try:
            # Find the null terminator or decode the whole array
            null_pos = c_char_array.value.find(b'\0')
            if null_pos != -1:
                return c_char_array.value[:null_pos].decode('utf-8', errors='replace')
            else:
                return c_char_array.value.decode('utf-8', errors='replace')
        except UnicodeDecodeError:
            return c_char_array.value.decode('latin-1', errors='replace') # Fallback to a more permissive decoding

    def _handle_inbound_event(self, cpu, data, size):
        event = ctypes.cast(data, ctypes.POINTER(InboundEvent)).contents
        self._process_message_event(event, inbound=True)

    def _handle_outbound_event(self, cpu, data, size):
        event = ctypes.cast(data, ctypes.POINTER(OutboundEvent)).contents
        self._process_message_event(event, inbound=False)

    def _process_message_event(self, event, inbound: bool):
        peer_id = event.peer_id
        message_type = self._get_decoded_string(event.message_type)
        message_size = event.message_size
        address = self._get_decoded_string(event.addr)

        if peer_id not in self.peers:
            # Placeholder for connection_type, as it's not directly available via tracepoint
            # In a real scenario, you'd likely fetch this from RPC or another source.
            connection_type = "unknown"
            self.peers[peer_id] = Peer(peer_id, address, connection_type)

        self.peers[peer_id].add_message(event.timestamp_ns, message_type, message_size, inbound)

        if not self.use_curses:
            ts = datetime.fromtimestamp(event.timestamp_ns / 1_000_000_000, tz=timezone.utc).strftime("%H:%M:%S.%f")[:-3]
            direction = "<---" if inbound else "--->"
            print(f"{ts} Peer {peer_id} ({address}) {direction} {message_type} ({message_size} bytes)")
        else:
            self._draw_ui()

    def _draw_ui(self):
        """Draws or updates the curses UI."""
        if not self.stdscr:
            return

        self.stdscr.erase()
        self.stdscr.border(0)

        # Draw header
        self.stdscr.addstr(0, 2, " Bitcoin Core P2P Monitor ", curses.A_BOLD)
        self.stdscr.addstr(0, self.stdscr.getmaxyx()[1] - 25, " Press 'q' to quit ", curses.A_BOLD)

        # Peer list window (left pane)
        max_y, max_x = self.stdscr.getmaxyx()
        peer_list_height = max_y - 4
        peer_list_width = max_x // 3
        self.peer_list_window = curses.newwin(peer_list_height, peer_list_width, 2, 1)
        self.peer_list_window.box()
        self.peer_list_window.addstr(0, 2, " Connected Peers ", curses.A_BOLD)
        self.peer_list_window.scrollok(True)
        self.peer_list_window.idlok(True)

        # Info window (right pane)
        info_height = max_y - 4
        info_width = max_x - peer_list_width - 2
        self.info_window = curses.newwin(info_height, info_width, 2, peer_list_width + 1)
        self.info_window.box()
        self.info_window.addstr(0, 2, " Peer Details ", curses.A_BOLD)
        self.info_window.scrollok(True)
        self.info_window.idlok(True)

        sorted_peers = sorted(self.peers.values(), key=lambda p: p.id)
        self.max_lines = len(sorted_peers)

        # Display peers in the left window
        for i, peer in enumerate(sorted_peers):
            if i < self.scroll:
                continue
            if i - self.scroll >= peer_list_height - 2: # Account for border
                break
            
            line = f" {peer.id:<3} {peer.address:<25} {peer.connection_type:<10}"
            attr = curses.A_NORMAL
            if peer.id == self.selected_peer_id:
                attr |= curses.A_REVERSE
            
            try:
                self.peer_list_window.addstr(i - self.scroll + 1, 1, line, attr)
            except curses.error:
                pass # Ignore if line goes out of bounds during resize


        # Display details of the selected peer in the right window
        selected_peer = self.peers.get(self.selected_peer_id)
        if selected_peer:
            self.info_window.erase()
            self.info_window.box()
            self.info_window.addstr(0, 2, " Peer Details ", curses.A_BOLD)
            self.info_window.addstr(1, 1, f"PEER {selected_peer.id} ({selected_peer.address})".center(info_width - 2), curses.A_REVERSE | curses.A_BOLD)
            self.info_window.addstr(2, 1, f"{'OUR NODE':<30} {'PEER':>30}", curses.A_BOLD)
            
            for i, msg in enumerate(selected_peer.last_messages):
                timestamp_str = datetime.fromtimestamp(msg.timestamp_ns / 1_000_000_000, tz=timezone.utc).strftime("%H:%M:%S.%f")[:-3]
                if msg.inbound:
                    self.info_window.addstr(i + 3, 1, f"{'':<30} <--- {msg.msg_type} ({msg.size} bytes) [{timestamp_str}]")
                else:
                    self.info_window.addstr(i + 3, 1, f" ---> {msg.msg_type} ({msg.size} bytes) [{timestamp_str}]")
            
        self.stdscr.refresh()
        self.peer_list_window.refresh()
        self.info_window.refresh()

    def _curses_wrapper(self, stdscr):
        """Wrapper for curses initialization and main loop."""
        self.stdscr = stdscr
        curses.noecho()
        curses.cbreak()
        self.stdscr.keypad(True)

        # Initial draw
        self._draw_ui()

        try:
            while True:
                self.bpf_instance.perf_buffer_poll(timeout=100) # Poll with a timeout
                key = self.stdscr.getch()
                if key == ord('q'):
                    break
                elif key == curses.KEY_UP:
                    self.scroll = max(0, self.scroll - 1)
                    self._draw_ui()
                elif key == curses.KEY_DOWN:
                    self.scroll = min(self.max_lines - (self.stdscr.getmaxyx()[0] - 4 - 2), self.scroll + 1) # Adjust for header/footer and box
                    self._draw_ui()
                elif key == curses.KEY_RIGHT:
                    # Select next peer
                    sorted_peer_ids = sorted(self.peers.keys())
                    if not sorted_peer_ids:
                        continue
                    
                    if self.selected_peer_id is None:
                        self.selected_peer_id = sorted_peer_ids[0]
                    else:
                        try:
                            current_index = sorted_peer_ids.index(self.selected_peer_id)
                            next_index = (current_index + 1) % len(sorted_peer_ids)
                            self.selected_peer_id = sorted_peer_ids[next_index]
                        except ValueError: # Selected peer might have disconnected
                            self.selected_peer_id = sorted_peer_ids[0]
                    self._draw_ui()
                elif key == curses.KEY_LEFT:
                    # Select previous peer
                    sorted_peer_ids = sorted(self.peers.keys())
                    if not sorted_peer_ids:
                        continue
                    
                    if self.selected_peer_id is None:
                        self.selected_peer_id = sorted_peer_ids[-1]
                    else:
                        try:
                            current_index = sorted_peer_ids.index(self.selected_peer_id)
                            prev_index = (current_index - 1 + len(sorted_peer_ids)) % len(sorted_peer_ids)
                            self.selected_peer_id = sorted_peer_ids[prev_index]
                        except ValueError:
                            self.selected_peer_id = sorted_peer_ids[-1]
                    self._draw_ui()


        finally:
            curses.endwin()

    def run(self):
        """Starts the P2P monitor."""
        if self.use_curses and curses:
            wrapper(self._curses_wrapper)
        else:
            print("Running in non-interactive (stdout only) mode.")
            print(f"{'Time (UTC)':<15} {'Peer ID':<9} {'Address':<40} {'Direction':<10} {'Message Type':<15} {'Size (bytes)':<15}")
            while True:
                try:
                    self.bpf_instance.perf_buffer_poll()
                except KeyboardInterrupt:
                    print("\nExiting...", file=sys.stderr)
                    break
                except Exception as e:
                    print(f"An unexpected error occurred: {e}", file=sys.stderr)
                    break
        
        if self.bpf_instance:
            self.bpf_instance.cleanup()
            print("BPF probes detached.", file=sys.stderr)

def main():
    parser = argparse.ArgumentParser(
        description="Monitor Bitcoin Core mempool events using eBPF tracepoints."
    )
    parser.add_argument(
        "pid", type=int, help="PID of the bitcoind process to monitor."
    )
    parser.add_argument(
        "--no-curses", action="store_true",
        help="Disable curses-based interactive output and print to stdout directly."
    )
    args = parser.parse_args()

    if args.pid <= 0:
        print("Error: PID must be a positive integer.", file=sys.stderr)
        sys.exit(1)

    # Check if bitcoind process exists
    if not os.path.exists(f"/proc/{args.pid}"):
        print(f"Error: Process with PID {args.pid} does not exist.", file=sys.stderr)
        sys.exit(1)

    monitor = P2PMonitor(args.pid, use_curses=not args.no_curses)
    monitor.run()

if __name__ == "__main__":
    main()