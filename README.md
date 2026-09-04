# traceuprobe

User-space memory-leak detection with eBPF uprobes: attach to a running
process, watch its `malloc` / `free` traffic, and report allocations that were
never released — without recompiling or restarting the target.

The usual alternatives all cost something this does not: `valgrind` slows the
target by an order of magnitude, `LD_PRELOAD` shims need a restart, and a
GCC-plugin static analyser cannot see allocations whose lifetime depends on
runtime input. A uprobe attaches to a live process and detaches again.

## How it works

1. A BPF program is attached to the target's allocator entry and return probes
   (`uprobe` / `uretprobe` on `malloc`, `free`).
2. Each allocation records size, address and the calling stack into a BPF hash
   map keyed by returned pointer.
3. `free` removes the matching entry.
4. What is left in the map when the tool detaches is the leak set, grouped by
   allocation site.

The interesting part is step 2: the return value is only available in the
*uretprobe*, while the size argument is only available in the *uprobe*, so the
size has to be stashed per-thread on entry and picked up again on return.

## Requirements

- Linux with BPF and uprobe support
- [bcc](https://github.com/iovisor/bcc) (`from bcc import BPF`)
- Root, or `CAP_BPF` + `CAP_PERFMON`

## Usage

```bash
sudo python3 bpftest.py
```

## Background reading

- <https://zhuanlan.zhihu.com/p/133854805>
- <https://ztex.medium.com/kprobe-%E7%AD%86%E8%A8%98-59d4bdb1e1fe>

## Related

This is the dynamic half of a pair. The static half —
[Static-analyzer-in-gccplugin](https://github.com/x213212/Static-analyzer-in-gccplugin)
— finds leaks at compile time by walking GCC's GIMPLE IR.

## License

MIT for the code in this repository. See [LICENSE](LICENSE).

`bcc` itself is Apache-2.0 and is not vendored here.
