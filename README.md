# EDK2 BrotliCustomDecompressLib — heap overflow (unfixed)

A heap-buffer-overflow in EDK2's own Brotli decompression glue
(`MdeModulePkg/Library/BrotliCustomDecompressLib`), present since 2017, unfixed
at HEAD as of 2026-10-25.  ASAN-confirmed with a proof-of-concept and an
end-to-end controlled-corruption demo.

## Summary

EDK2's Brotli wrapper reads the decompressed output size from an
attacker-controlled GUIDed section header, truncates it UINT64 → UINT32 with no
guard, and passes it to the DXE core which allocates a buffer of that size.
`BrotliDecompressInternal` then decompresses into that buffer **unbounded** — it
runs until the Brotli stream ends, writing past the allocation.

**Result:** heap overflow (write primitive) in the DXE phase, before Secure Boot
verification completes.  An attacker who controls the firmware image (flash, capsule,
or ESP) can overwrite adjacent pool objects — function pointers, security flags,
protocol structures — with chosen bytes.

This is the overlooked Brotli sibling of **CVE-2021-28211** (LZMA got a
`>MAX_UINT32` guard in 2021; Brotli never did).  A variant sweep confirms Brotli
is the **only** EDK2 decompressor that lacks both the truncation guard and an
output bound.

## Affected code

| File | What it does |
|------|-------------|
| `BrotliDecompress.c:238` | Casts UINT64 decoded size to UINT32 — no `MAX_UINT32` guard |
| `BrotliDecompress.c:118–157` | Decompresses into the destination buffer with no bound check |
| `GuidedSectionExtraction.c` | Calls `GetInfo` then `Decompress` — trusts the declared size |
| `CoreSectionExtraction.c:1597` | Allocates the destination buffer at the declared size |

All in `tianocore/edk2`, `MdeModulePkg/Library/BrotliCustomDecompressLib`.

## Evidence

| Artifact | Description |
|----------|-------------|
| [`harness/edk2_brotli_overflow_poc.c`](harness/edk2_brotli_overflow_poc.c) | ASAN proof-of-concept: 4096-byte stream into 64-byte buffer |
| [`harness/asan_output.txt`](harness/asan_output.txt) | ASAN output: `heap-buffer-overflow` at `BrotliDecompressInternal` → `memcpy` |
| [`harness/edk2_brotli_overflow_demo.c`](harness/edk2_brotli_overflow_demo.c) | End-to-end demo: controlled corruption of adjacent pool objects |
| [`harness/demo_output.txt`](harness/demo_output.txt) | Demo output: function pointers hijacked, Secure Boot disabled |
| [`harness/lvfs_brotli_scan.py`](harness/lvfs_brotli_scan.py) | LVFS firmware scanner (blast-radius measurement) |
| [`harness/lvfs_scan_output.txt`](harness/lvfs_scan_output.txt) | Scan results: 0/200 firmware images use Brotli |
| [`evidence/`](evidence/) | Copies of the vulnerable EDK2 source files at HEAD |
| [`FINDINGS.md`](FINDINGS.md) | Full write-up: line references, prior-art search, variant sweep, LZMA audit |

## Blast radius

**Narrow.**  Two independent surveys found zero platforms that use Brotli GUIDed
sections in practice:

- **GitHub code search** (all public repos): 0 platform DSC files reference
  `BrotliCustomDecompressLib`.  Every hit is `MdeModulePkg.dsc` itself.
- **LVFS firmware scan** (200 shipping images, 9 vendors): Brotli GUID found in
  **0/200** images.  LZMA (positive control) found in **161/200**.

The vulnerable code ships in the EDK2 tree but is dead code today — added in 2017,
never adopted by IBVs or OEMs.  The bug is real and exploitable in principle; if
Brotli adoption increases, it becomes immediately reachable.

## Fix

Two changes, matching what LZMA and Tiano already have:

1. **Add the `MAX_UINT32` guard** to `BrotliUefiDecompressGetInfo`
   (`BrotliDecompress.c:238`): reject decoded sizes > `MAX_UINT32`, as
   `LzmaDecompress.c:149` does since CVE-2021-28211.
2. **Bound the output** in `BrotliDecompressInternal`: track bytes written and
   stop at `DestinationSize`, as the Tiano decompressor does with `mOrigSize`.

## Reproduce

Build the PoC on Linux with libbrotli and GCC:

```bash
# ASAN proof (aborts at the overflow)
gcc -fsanitize=address -g -O1 -o poc harness/edk2_brotli_overflow_poc.c \
    -lbrotlienc -lbrotlidec
./poc

# Controlled-corruption demo (completes the overflow, shows the damage)
gcc -g -O1 -o demo harness/edk2_brotli_overflow_demo.c \
    -lbrotlienc -lbrotlidec
./demo
```

## Prior art

- **CVE-2021-28211** — the LZMA sibling, fixed in 2021.  The Brotli path was
  overlooked.
- **CVE-2026-111497** — a separate upstream Brotli decoder bug (9.2).  EDK2 is
  also affected (issue #13378), but that is a different finding.
- No public CVE, advisory, issue, or PR addresses the Brotli glue overflow.
  Checked: all 14 EDK2 GHSAs, all 29 Brotli issues, all 28 Brotli PRs,
  CVE/NVD, EDK2 HEAD.

## Disclosure

Full public disclosure, 2026-10-26.  No coordinated disclosure period was given
to TianoCore.  The narrow blast radius (zero shipping firmware affected) and the
fact that the sibling LZMA bug has been public since 2021 informed this decision.

## Author

Luc Music ([@lukr54](https://github.com/lukr54))
