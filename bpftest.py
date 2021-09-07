#!/usr/bin/python

from __future__ import print_function

import ctypes as ct
from bcc import BPF
from time import sleep
from datetime import datetime
import resource
import argparse
import subprocess
import os
import sys
text = """
#include <uapi/linux/ptrace.h>

struct data_t {
    int a;
    int b;
    int uninit_c;
    int t;
    u64 IPAddr;
};

BPF_PERF_OUTPUT(events);

int test(struct pt_regs *ctx) {
    struct data_t data = {};

    u64 *bp = (u64 *)(ctx->bp) ;
    u64 *di = (u64 *)(ctx->di) ;
    u64 *si = (u64 *)(ctx->si) ;
    u64 *sp = (u64 *)PT_REGS_SP(ctx) ;
    u64 *fp = (u64 *)PT_REGS_FP(ctx);
    
    data.a = di;
    data.b =  si;

    data.IPAddr = (u64 *)PT_REGS_IP(ctx);

    bpf_probe_read(&data.uninit_c, sizeof(data.uninit_c),
     bp - 1);
    bpf_probe_read(&data.t, sizeof(data.t),
     bp - 2);
    bpf_trace_printk("SPEN addr = %x\\n", PT_REGS_IP(ctx));
    events.perf_submit(ctx, &data, sizeof(struct data_t));
    return 0;
}

int test2(struct pt_regs *ctx) {
    struct data_t data = {};

    u64 *bp = (u64 *)(ctx->bp) ;
    u64 *di = (u64 *)(ctx->di) ;
    u64 *si = (u64 *)(ctx->si) ;
    u64 *sp = (u64 *)PT_REGS_SP(ctx) ;
    u64 *fp = (u64 *)PT_REGS_FP(ctx);
    
    data.a = di;
    data.b =  si;

    data.IPAddr = (u64 *)PT_REGS_IP(ctx);

    bpf_probe_read(&data.uninit_c, sizeof(data.uninit_c),
     bp - 1);
    bpf_probe_read(&data.t, sizeof(data.t),
     bp - 2);
    bpf_trace_printk("SPEN addr = %x\\n", PT_REGS_IP(ctx));
    events.perf_submit(ctx, &data, sizeof(struct data_t));
    return 0;
}
"""

examples = """
EXAMPLES:

./memleak -p $(pidof allocs)
        Trace allocations and display a summary of "leaked" (outstanding)
        allocations every 5 seconds
./memleak -p $(pidof allocs) -t
        Trace allocations and display each individual allocator function call
./memleak -ap $(pidof allocs) 10
        Trace allocations and display allocated addresses, sizes, and stacks
        every 10 seconds for outstanding allocations
./memleak -c "./allocs"
        Run the specified command and trace its allocations
./memleak
        Trace allocations in kernel mode and display a summary of outstanding
        allocations every 5 seconds
./memleak -o 60000
        Trace allocations in kernel mode and display a summary of outstanding
        allocations that are at least one minute (60 seconds) old
./memleak -s 5
        Trace roughly every 5th allocation, to reduce overhead
"""

description = """

Trace outstanding memory allocations that weren't freed.
Supports both user-mode allocations made with libc functions and kernel-mode
allocations made with kmalloc/kmem_cache_alloc/get_free_pages and corresponding
memory release functions.
"""
parser = argparse.ArgumentParser(description=description,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples)
parser.add_argument("-O", "--obj", type=str, default="c",
        help="attach to allocator functions in the specified object")
args = parser.parse_args()
obj = args.obj
b = BPF(text=text)
b.attach_uprobe(name=obj, sym="foo", fn_name="test")
#b.attach_uretprobe(name=obj, sym="foo", fn_name="test2")
class Data(ct.Structure):
    _fields_ = [
        ("a", ct.c_int),
        ("b", ct.c_int),
        ("uninit_c", ct.c_int),
        ("t", ct.c_int),
        ("IPAddr", ct.c_longlong),
    ]

def print_event(cpu, data, size):

    event = ct.cast(data, ct.POINTER(Data)).contents
    print("a: %d, b: %d, uninit_c: %d, t: %d, ipaddress: %d" % (event.a, event.b, event.uninit_c, event.t, event.IPAddr))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    b.kprobe_poll()
