#!/usr/bin/env python3
# Copyright (c) 2021-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import sys
import ctypes
from bcc import BPF, USDT

"""
Example logging Bitcoin Core utxo set cache flushes utilizing
the utxocache:flush tracepoint.

USAGE:  ./contrib/tracing/log_utxocache_flush.py path/to/bitcoind
"""

# BPF: The C program to be compiled to an eBPF program (by BCC) and loaded into
# a sandboxed Linux kernel VM.
BPF_PROGRAM = """
# include <uapi/linux/ptrace.h>

struct data_t
{
  u64 duration;
  u32 mode;
  u64 coins_count;
  u64 coins_mem_usage;
  bool is_flush_for_prune;
};

// BPF perf buffer to push the data to user space.
BPF_PERF_OUTPUT(flush);

int trace_flush(struct pt_regs *ctx) {
  struct data_t data = {};
  bpf_usdt_readarg(1, ctx, &data.duration);
  bpf_usdt_readarg(2, ctx, &data.mode);
  bpf_usdt_readarg(3, ctx, &data.coins_count);
  bpf_usdt_readarg(4, ctx, &data.coins_mem_usage);
  bpf_usdt_readarg(5, ctx, &data.is_flush_for_prune);
  flush.perf_submit(ctx, &data, sizeof(data));
  return 0;
}
"""

# Mapping for flush modes (from src/kernel/messagestartchars.h, if applicable)
FLUSH_MODES = {
    0: "NONE",
    1: "IF_NEEDED",
    2: "ALWAYS",
    3: "PERIODIC",
}


class FlushEvent(ctypes.Structure):
    """
    Structure to represent a utxocache flush event data received from eBPF.
    Corresponds to 'struct data_t' in the BPF_PROGRAM.
    """
    _fields_ = [
        ("duration", ctypes.c_uint64),
        ("mode", ctypes.c_uint32),
        ("coins_count", ctypes.c_uint64),
        ("coins_mem_usage", ctypes.c_uint64),
        ("is_flush_for_prune", ctypes.c_bool),
    ]


def print_event(event: FlushEvent):
    """
    Prints the details of a utxocache flush event.
    """
    mode_str = FLUSH_MODES.get(event.mode, "UNKNOWN")
    print(f"{event.duration:<15} {mode_str:<10} {event.coins_count:<15} "
          f"{event.coins_mem_usage/1000:>14.2f} kB {event.is_flush_for_prune:<8}")


def main(pid: str):
    """
    Hooks into bitcoind process and logs utxocache flush events.
    """
    print(f"Hooking into bitcoind with pid {pid}")

    try:
        bitcoind_with_usdts = USDT(pid=int(pid))
    except Exception as e:
        print(f"Error attaching to PID {pid}: {e}")
        print("Please ensure bitcoind is running and the user has "
              "appropriate permissions (e.g., sudo).")
        sys.exit(1)

    # Attach the trace functions defined in the BPF program to the tracepoints
    bitcoind_with_usdts.enable_probe(probe="flush", fn_name="trace_flush")

    bpf_instance = None
    try:
        bpf_instance = BPF(text=BPF_PROGRAM, usdt_contexts=[bitcoind_with_usdts])

        def handle_flush(_, data, size):
            """
            Coins Flush handler.
            Called each time coin caches and indexes are flushed.
            """
            event = ctypes.cast(data, ctypes.POINTER(FlushEvent)).contents
            print_event(event)

        bpf_instance["flush"].open_perf_buffer(handle_flush)
        print("Logging utxocache flushes. Ctrl-C to end...")
        print(f"{'Duration (ns)':<15} {'Mode':<10} {'Coins Count':<15} "
              f"{'Memory Usage':<15} {'For Prune':<8}")

        while True:
            bpf_instance.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        if bpf_instance:
            # Detach probes when exiting
            bpf_instance.cleanup()
            print("BPF probes detached.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("USAGE: ./contrib/tracing/log_utxocache_flush.py <PID_OF_BITCOIND>")
        sys.exit(1)

    main(sys.argv[1])