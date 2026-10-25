# EDK2 BrotliCustomDecompressLib — security findings

Status (2026-10-25): **Finding A CONFIRMED** (n-day, DUP); **Finding B CONFIRMED** (novel,
ASAN-proven heap-buffer-overflow). Defensive research, for coordinated disclosure to
TianoCore/EDK2.

Target: `tianocore/edk2`, `MdeModulePkg/Library/BrotliCustomDecompressLib` + the MdePkg decompress
libs. Why it matters: EDK2 is the open UEFI reference that AMI/Insyde/Phoenix build on;
`BrotliCustomDecompressLib` decompresses Brotli-compressed GUIDed FV sections during boot — in the
DXE/PEI section-extraction path, before Secure Boot completes.

## Finding A — vendored Brotli carries CVE-2026-111497 (CONFIRMED)

EDK2 pins `google/brotli` as a submodule at commit `e230f474b87134e8c6c85b630084c612057f253e`.
- Version: **Brotli 1.2.0** (`c/common/version.h`), commit dated **2025-11-03**.
- **CVE-2026-111497** = out-of-bounds write in the Brotli decoder (`c/dec/decode.c`, block-switch
  handling), CVSS 4.0 **9.2**; affects brotli **1.0.3–1.2.0**; fixed in **1.0.10 / 1.1.1 / 1.2.1**.
- EDK2's 1.2.0 is in the affected range, one release below the 1.2.1 fix.
- **Fix marker ABSENT**: the patched `decode.h` defines `BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH`
  (-17); a grep of the fetched submodule tree for `BLOCK_SWITCH` returned nothing → unpatched, no
  backport.

=> EDK2 (and IBV firmware derived from it) using `BrotliCustomDecompressLib` ships a Brotli decoder
vulnerable to the 9.2 OOB write, reachable via a malicious Brotli-compressed GUIDed section
(firmware image / capsule).

Class: **n-day** (known upstream bug reaching firmware), not a novel discovery.
**Reported independently** as edk2 issue #13378 (2026-10-24) — treat as a DUP; EDK2 is already aware. Drop it.
Fix: bump the Brotli submodule to >= 1.2.1 (or backport the block-switch fix).
Note: "recently updated" (1.2.0, Nov 2025) quietly became "one version behind a 9.2" when the CVE
landed in Oct 2026 — version-skew is the gap to the latest *fix*, not the age of the pin.

## Finding B — EDK2 Brotli glue: attacker-declared output size, unbounded decompress (CANDIDATE)

In EDK2's own wrapper (`BrotliDecompress.c`, `GuidedSectionExtraction.c`; Intel 2017–2018),
independent of the decoder version:
- `BrotliUefiDecompressGetInfo` reads the decompressed size from the attacker-controlled section
  header (`BrGetDecodedSizeOfBuf`, lines 174–191), cast **UINT64 -> UINT32** (`BrotliDecompress.c:238`).
  No validation.
- The core section-extraction infra allocates `OutputBuffer` = that size; `BrotliGuidedSectionExtraction`
  passes it to `BrotliUefiDecompress` -> `BrotliDecompressInternal` (`GuidedSectionExtraction.c:155–180`).
- `BrotliDecompressInternal` decompresses into `OutputBuffer`, advancing by `FILE_BUFFER_SIZE` per
  chunk (`BrotliDecompress.c:118–157`) with **no bound against the declared size** — it runs until the
  stream ends.

=> Heap overflow (write primitive): declare a small `OutputBufferSize` (or use the UINT32 truncation,
e.g. header `0x1_0000_0040` -> 64-byte buffer) and ship a stream that decompresses larger -> the loop
writes past `OutputBuffer`. In EDK2's own code, not upstream brotli -> not covered by brotli's
OSS-Fuzz; EDK2 ships no in-tree fuzzing (confirmed: no `*Fuzz*` files in the tree).

Status: **CONFIRMED (2026-10-25).** ASAN proof in `harness/`: a 4096-byte Brotli stream declared as
64 bytes overflows the heap by 4032 bytes at the final-flush `CopyMem` (BrotliDecompress.c:156).
Stack trace: `memcpy → BrotliDecompressInternal → BrotliUefiDecompress`. See `harness/asan_output.txt`.

### Finding B — prior art (checked 2026-10-25)
- No public CVE/advisory names the Brotli glue bug (CVE/NVD/web search).
- CVE-2026-97631 (9.5, "copy into output buffer without size check") is a NetworkPkg **ICMP/PXE** bug
  (per the Microsoft mu_basecore backport + Positive Technologies), **not** the decompression path.
- **Sibling: CVE-2021-28211** — heap overflow in `LzmaUefiDecompressGetInfo`, fixed 2021
  (stable202011, commit e7bd0dd). The fix added `if (DecodedSize > MAX_UINT32) return RETURN_UNSUPPORTED;`
  to the LZMA GetInfo (`LzmaDecompress.c:149`). The identical Brotli GetInfo **never got this guard** —
  still `*DestinationSize = (UINT32)GetSize` unchecked (`BrotliDecompress.c:238`); and the Brotli
  decompress loop is unbounded where LZMA's decoder is size-bounded.
  => Finding B is the overlooked Brotli sibling of CVE-2021-28211, live and unpatched at HEAD.
  Patch-gap-flavored (not fully virgin), but unpublished and write-capable.
- **Authoritative absence check (2026-10-25, done):** all 14 EDK2 GitHub Security Advisories reviewed —
  none touch decompression/Brotli/LZMA/GUIDed sections (the 9.5, GHSA-99cj-7hg9-mp4m, is the PXE driver).
  Issue #13378 is purely the decoder CVE (Finding A), NOT the glue. No fix among the 28 Brotli PRs
  (submodule bumps + build fixes + scratch-free #6509, none bounding output). HEAD unpatched. TianoCore
  Bugzilla decommissioned (migrated to GitHub). => **Finding B is unreported and unfixed in all public
  channels.** Caveat: private/draft advisories are not visible.
- **Exhaustive scan (2026-10-25):** all 29 Brotli issues + 28 Brotli PRs reviewed. Only near-miss is
  **#8608** (Bugzilla 2946, 2020): after the submodule move the *compressor* stopped writing the size
  header, so legitimate decompression read garbage ("too-large") sizes and builds failed; fixed
  compressor-side (commit 9cd854e / PRs #1648, #1101, #1123). That is a FUNCTIONAL regression, NOT the
  decompressor-side security bound — Finding B is untouched by it (if anything #8608 entrenched the
  "trust the header size" design). Everything else is build/CI noise.

### Variant sweep — the other EDK2 decompressors (checked 2026-10-25)
- **Tiano/UEFI** (`BaseUefiDecompressLib`): SAFE. `Decode` bounds every output write with
  `if (mOutBuf >= mOrigSize) goto Done;` (lines 580 / 610 / 627); size field is native UINT32 (no truncation).
- **LZMA** (`LzmaCustomDecompressLib`): SAFE. GetInfo has the MAX_UINT32 guard (:149); `LzmaDecode`
  respects the destination length (`:203`), bounding output.
- => **Brotli is the unique outlier** — the only codec that neither guards the UINT32 truncation nor
  bounds output to the declared size. Confirms B is a specific omission, not an EDK2-wide pattern; the
  fix is to match LZMA/Tiano (bound output + add the MAX_UINT32 guard). The sweep did NOT expand blast
  radius (the ubiquitous Tiano path is safe), so B stays Brotli-specific and reachability-gated.

## Disclosure
EDK2's documented security process (TianoCore Bugzilla security flag; confirm the current channel at
submission). Coordinate a timeline; no public PoC before a fix.

## Re-setup
`git clone --depth 1 https://github.com/tianocore/edk2`
Evidence copies in `evidence/`: `BrotliDecompress.c`, `GuidedSectionExtraction.c`,
`BaseUefiDecompressLib.c` (the native Tiano decompress — read, appears hardened: `MakeTable` bounds
checks present).
