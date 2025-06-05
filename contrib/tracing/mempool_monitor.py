#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Example logging Bitcoin Core mempool events using the mempool:added,
mempool:removed, mempool:replaced, and mempool:rejected tracepoints.

USAGE:  ./contrib/tracing/mempool_monitor.py <PID_OF_BITCOIND> [--no-curses]
"""

import argparse
import ctypes
import sys
from datetime import datetime, timezone

# Optional: curses for interactive TUI, if available
try:
    import curses
except ImportError:
    curses = None
    print("Warning: 'curses' module not found. Running in non-interactive mode. "
          "Install with 'pip install windows-curses' on Windows or 'pip install curses' "
          "on Linux if you want interactive TUI.")

from bcc import BPF, USDT

# Constants for BPF program and event data structures
HASH_LENGTH = 32
MAX_REJECT_REASON_LENGTH = 118
MAX_REMOVAL_REASON_LENGTH = 9

# BPF C program for tracing mempool events
BPF_PROGRAM = f"""
#include <uapi/linux/ptrace.h>

#define HASH_LENGTH {HASH_LENGTH}
#define MAX_REJECT_REASON_LENGTH {MAX_REJECT_REASON_LENGTH}
#define MAX_REMOVAL_REASON_LENGTH {MAX_REMOVAL_REMOVAL_REASON_LENGTH}

// Structure for a new transaction added to the mempool
struct added_event
{{
  u8    hash[HASH_LENGTH];
  s32   vsize;
  s64   fee;
  u64   entry_time; // Timestamp when the transaction entered the mempool
}};

// Structure for a transaction removed from the mempool
struct removed_event
{{
  u8    hash[HASH_LENGTH];
  char  reason[MAX_REMOVAL_REASON_LENGTH + 1];
}};

// Structure for a transaction rejected from the mempool
struct rejected_event
{{
  u8    hash[HASH_LENGTH];
  char  reason[MAX_REJECT_REASON_LENGTH + 1];
}};

// Structure for a transaction replaced in the mempool (RBF)
struct replaced_event
{{
  u8    replaced_hash[HASH_LENGTH];
  s32   replaced_vsize;
  s64   replaced_fee;
  u64   replaced_entry_time;
  u8    replacement_hash[HASH_LENGTH];
  s32   replacement_vsize;
  s64   replacement_fee;
}};

// BPF perf buffers to push event data to user space
BPF_PERF_OUTPUT(added);
BPF_PERF_OUTPUT(removed);
BPF_PERF_OUTPUT(replaced);
BPF_PERF_OUTPUT(rejected);

// Tracepoint for transaction added to mempool
int trace_added(struct pt_regs *ctx) {{
  struct added_event event = {{}};
  bpf_usdt_readarg(1, ctx, &event.hash);
  bpf_usdt_readarg(2, ctx, &event.vsize);
  bpf_usdt_readarg(3, ctx, &event.fee);
  bpf_usdt_readarg(4, ctx, &event.entry_time);
  added.perf_submit(ctx, &event, sizeof(event));
  return 0;
}}

// Tracepoint for transaction removed from mempool
int trace_removed(struct pt_regs *ctx) {{
  struct removed_event event = {{}};
  bpf_usdt_readarg(1, ctx, &event.hash);
  bpf_usdt_readarg(2, ctx, &event.reason);
  removed.perf_submit(ctx, &event, sizeof(event));
  return 0;
}}

// Tracepoint for transaction rejected from mempool
int trace_rejected(struct pt_regs *ctx) {{
  struct rejected_event event = {{}};
  bpf_usdt_readarg(1, ctx, &event.hash);
  bpf_usdt_readarg(2, ctx, &event.reason);
  rejected.perf_submit(ctx, &event, sizeof(event));
  return 0;
}}

// Tracepoint for transaction replaced in mempool
int trace_replaced(struct pt_regs *ctx) {{
  struct replaced_event event = {{}};
  bpf_usdt_readarg(1, ctx, &event.replaced_hash);
  bpf_usdt_readarg(2, ctx, &event.replaced_vsize);
  bpf_usdt_readarg(3, ctx, &event.replaced_fee);
  bpf_usdt_readarg(4, ctx, &event.replaced_entry_time);
  bpf_usdt_readarg(5, ctx, &event.replacement_hash);
  bpf_usdt_readarg(6, ctx, &event.replacement_vsize);
  bpf_usdt_readarg(7, ctx, &event.replacement_fee);
  replaced.perf_submit(ctx, &event, sizeof(event));
  return 0;
}}
"""

# Ctypes structures for Python to interpret BPF event data
class AddedEvent(ctypes.Structure):
    _fields_ = [
        ("hash", ctypes.c_ubyte * HASH_LENGTH),
        ("vsize", ctypes.c_int32),
        ("fee", ctypes.c_int64),
        ("entry_time", ctypes.c_uint64),
    ]

class RemovedEvent(ctypes.Structure):
    _fields_ = [
        ("hash", ctypes.c_ubyte * HASH_LENGTH),
        ("reason", ctypes.c_char * (MAX_REMOVAL_REASON_LENGTH + 1)),
    ]

class RejectedEvent(ctypes.Structure):
    _fields_ = [
        ("hash", ctypes.c_ubyte * HASH_LENGTH),
        ("reason", ctypes.c_char * (MAX_REJECT_REASON_LENGTH + 1)),
    ]

class ReplacedEvent(ctypes.Structure):
    _fields_ = [
        ("replaced_hash", ctypes.c_ubyte * HASH_LENGTH),
        ("replaced_vsize", ctypes.c_int32),
        ("replaced_fee", ctypes.c_int64),
        ("replaced_entry_time", ctypes.c_uint64),
        ("replacement_hash", ctypes.c_ubyte * HASH_LENGTH),
        ("replacement_vsize", ctypes.c_int32),
        ("replacement_fee", ctypes.c_int64),
    ]

class MempoolMonitor:
    """
    Monitors Bitcoin Core mempool events and prints them to console or a TUI.
    """
    def __init__(self, pid: int, use_curses: bool = True):
        self.pid = pid
        self.use_curses = use_curses
        self.stdscr = None
        self.bpf_instance = None

        print(f"Hooking into bitcoind with pid {self.pid}")

        try:
            # Attach USDT probes to the bitcoind process
            self.bitcoind_with_usdts = USDT(pid=self.pid)
            self.bitcoind_with_usdts.enable_probe(probe="added", fn_name="trace_added")
            self.bitcoind_with_usdts.enable_probe(probe="removed", fn_name="trace_removed")
            self.bitcoind_with_usdts.enable_probe(probe="replaced", fn_name="trace_replaced")
            self.bitcoind_with_usdts.enable_probe(probe="rejected", fn_name="trace_rejected")

            # Load the BPF program
            self.bpf_instance = BPF(text=BPF_PROGRAM, usdt_contexts=[self.bitcoind_with_usdts])

            # Open perf buffers for each event type
            self.bpf_instance["added"].open_perf_buffer(self._handle_added_event)
            self.bpf_instance["removed"].open_perf_buffer(self._handle_removed_event)
            self.bpf_instance["replaced"].open_perf_buffer(self._handle_replaced_event)
            self.bpf_instance["rejected"].open_perf_buffer(self._handle_rejected_event)

        except Exception as e:
            print(f"Error initializing BPF: {e}", file=sys.stderr)
            print("Ensure bitcoind is running and you have sufficient permissions (e.g., sudo).", file=sys.stderr)
            sys.exit(1)

    def _format_event(self, event_type: str, data) -> str:
        """Helper to format event data into a readable string."""
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3] # Current time in HH:MM:SS.miliseconds

        try:
            # Decode reason strings safely
            reason_decoded = data.reason.decode('utf-8', errors='replace')
        except AttributeError:
            reason_decoded = "" # Not all events have a reason field

        if event_type == "added":
            return (
                f"{ts} added {bytes(data.hash)[::-1].hex()} "
                f"feerate {data.fee / data.vsize:.2f} sat/vB "
                f"({data.fee} sat, {data.vsize} vbytes)"
            )
        elif event_type == "removed":
            return (
                f"{ts} removed {bytes(data.hash)[::-1].hex()} "
                f"reason: {reason_decoded}"
            )
        elif event_type == "rejected":
            return (
                f"{ts} rejected {bytes(data.hash)[::-1].hex()} "
                f"reason: {reason_decoded}"
            )
        elif event_type == "replaced":
            # Convert entry_time from ns to seconds, then calculate age
            current_timestamp = datetime.now(timezone.utc).timestamp()
            replaced_age = (current_timestamp - (data.replaced_entry_time / 1_000_000_000)) if data.replaced_entry_time > 0 else 0
            replacement_age = (current_timestamp - (data.entry_time / 1_000_000_000)) if hasattr(data, 'entry_time') and data.entry_time > 0 else 0 # assuming replacement has entry_time from added event

            return (
                f"{ts} replaced {bytes(data.replaced_hash)[::-1].hex()} "
                f"with feerate {data.replaced_fee / data.replaced_vsize:.2f} sat/vB "
                f"({data.replaced_fee} sat, {data.replaced_vsize} vbytes) "
                f"received {replaced_age:.1f} seconds ago "
                f"with {bytes(data.replacement_hash)[::-1].hex()} "
                f"with feerate {data.replacement_fee / data.replacement_vsize:.2f} sat/vB "
                f"({data.replacement_fee} sat, {data.replacement_vsize} vbytes)"
            )
        else:
            return f"{ts} Unsupported event type: {event_type}"

    def _handle_event(self, cpu, data, size, event_type: str, EventClass):
        """Generic handler for BPF perf buffer events."""
        event = ctypes.cast(data, ctypes.POINTER(EventClass)).contents
        formatted_line = self._format_event(event_type, event)
        if self.use_curses:
            self.stdscr.addstr(formatted_line + "\n")
            self.stdscr.refresh()
        else:
            print(formatted_line)

    def _handle_added_event(self, cpu, data, size):
        self._handle_event(cpu, data, size, "added", AddedEvent)

    def _handle_removed_event(self, cpu, data, size):
        self._handle_event(cpu, data, size, "removed", RemovedEvent)

    def _handle_rejected_event(self, cpu, data, size):
        self._handle_event(cpu, data, size, "rejected", RejectedEvent)

    def _handle_replaced_event(self, cpu, data, size):
        self._handle_event(cpu, data, size, "replaced", ReplacedEvent)

    def run(self):
        """Starts monitoring mempool events."""
        print("Logging mempool events. Ctrl-C to end...")
        if self.use_curses and curses:
            try:
                self.stdscr = curses.initscr()
                curses.noecho()
                curses.cbreak()
                self.stdscr.keypad(True)
                self.stdscr.scrollok(True)
                self.stdscr.idlok(True)
                self.stdscr.addstr("Logging mempool events. Ctrl-C to end...\n")
                self.stdscr.addstr(f"{'Time (UTC)':<15} {'Type':<10} {'Details'}\n")
                self.stdscr.refresh()
            except Exception as e:
                print(f"Error initializing curses: {e}. Falling back to standard output.", file=sys.stderr)
                self.use_curses = False
                if self.stdscr:
                    curses.endwin()
                    self.stdscr = None

        try:
            while True:
                self.bpf_instance.perf_buffer_poll()
        except KeyboardInterrupt:
            print("\nExiting...", file=sys.stderr)
        finally:
            if self.bpf_instance:
                self.bpf_instance.cleanup()
                print("BPF probes detached.", file=sys.stderr)
            if self.use_curses and self.stdscr:
                curses.endwin()

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

    # Basic PID validation
    if args.pid <= 0:
        print("Error: PID must be a positive integer.", file=sys.stderr)
        sys.exit(1)

    monitor = MempoolMonitor(args.pid, use_curses=not args.no_curses)
    monitor.run()

if __name__ == "__main__":
    main()