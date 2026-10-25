# EDK2 BrotliCustomDecompressLib — Security Findings

Defensive security research for coordinated disclosure to TianoCore/EDK2.

**Status (2026-10-25):** Two findings in `MdeModulePkg/Library/BrotliCustomDecompressLib`.

| Finding | Class | Status | Disposition |
|---------|-------|--------|-------------|
| A — Vendored Brotli CVE-2026-111497 | n-day | Confirmed | **DUP** — independently reported as edk2 #13378 (2026-10-24). Dropped. |
| B — Glue heap overflow (UINT64→UINT32 truncation + unbounded decompress) | Novel | **ASAN-confirmed** | **Unreported + unfixed** in all public channels. 4032-byte heap overflow proven. |

## Finding B — the real finding

EDK2's own Brotli wrapper (`BrotliDecompress.c`, `GuidedSectionExtraction.c`, Intel 2017–2018)
reads the decompressed output size from the attacker-controlled GUIDed section header, truncates
it UINT64→UINT32, and passes it to the DXE core which allocates a buffer of that size.
`BrotliDecompressInternal` then decompresses into that buffer with **no bound against the
declared size** — it runs until the Brotli stream ends.

**Result:** heap overflow (write primitive) in the DXE phase, before Secure Boot completes.

This is the overlooked Brotli sibling of **CVE-2021-28211** (LZMA got a `>MAX_UINT32` guard in
2021; Brotli never did). A variant sweep confirms Brotli is the **only** EDK2 decompressor that
lacks both the truncation guard and an output bound.

## Blast radius

**NARROW.** Two independent surveys (GitHub code search across all public repos + binary GUID scan of
200 shipping firmware images from LVFS) found **zero** platforms that actually use Brotli GUIDed
sections. LZMA (the positive control) was present in 161/200 images. The vulnerable code ships in
the EDK2 tree but is dead code in practice — a dormant vulnerability. See FINDINGS.md for details.

## Repository contents

```
FINDINGS.md              Full write-up with line references, prior-art, and blast-radius analysis
evidence/
  BrotliDecompress.c     Vulnerable glue (BrotliDecompressInternal + GetInfo)
  GuidedSectionExtraction.c   GUIDed section handler that calls the glue
  BaseUefiDecompressLib.c     Tiano/UEFI decompress (safe — output-bounded; control)
harness/
  edk2_brotli_overflow_poc.c   ASAN proof-of-concept (sanitizer evidence)
  asan_output.txt              ASAN output showing heap-buffer-overflow
  edk2_brotli_overflow_demo.c  End-to-end demo: controlled corruption of adjacent pool objects
  demo_output.txt              Demo output: function pointers hijacked, Secure Boot disabled
  lvfs_brotli_scan.py          LVFS firmware binary scanner (Brotli vs LZMA GUID search)
  lvfs_scan_output.txt         Scan results: 0/200 Brotli, 161/200 LZMA
```

## Disclosure

This repository is **private**. No public PoC before a fix is available.
Disclosure target: TianoCore/EDK2 security process (GitHub Security Advisory or security@tianocore.org).
