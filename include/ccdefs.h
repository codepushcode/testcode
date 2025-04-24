#ifndef defs_h_
#define defs_h_

#include <stdint.h>

typedef uint32_t PIMKey_t;
typedef uint32_t PIMValue_t;

#define KiB (1 << 10)
#define MiB (KiB << 10)

#define DIVCEIL(n, d) (((n) - 1) / (d) + 1)

#define NR_DPUS 1
#define NR_TASKLETS 16
#define NR_OPERATIONS 1000

#define NR_KERNELS 3
#define MAX_MRAM_SIZE (48 * MiB)
#define WRAM_BUFFER_SIZE 512

#define BUCKET_HEADER_SKIP 2
#define ENTRIES_PER_BUCKET_PIM 14
#define BUCKET_ENTRY_SIZE sizeof(BucketEntry)
#define BUCKET_SIZE sizeof(Bucket)
#define KEY_SIZE sizeof(PIMKey_t)

#define BUCKETS_PER_CHUNK 1024
#define NR_KEYS_PER_WRAM_BUFFER (WRAM_BUFFER_SIZE / KEY_SIZE)
#define CHUNK_SIZE (BUCKETS_PER_CHUNK * BUCKET_SIZE)
#define MAX_NUM_CHUNKS (MAX_MRAM_SIZE / CHUNK_SIZE)
#define BITMAP_LEN DIVCEIL(MAX_NUM_CHUNKS, 32)

#define MAX_NUM_SCHUNKS DIVCEIL(MAX_NUM_CHUNKS, BUCKETS_PER_CHUNK)
#define CHUNKS_PER_STASH 512
#define MAX_VCHUNK_DEGREE 11
#define INIT_GLOBAL_DEPTH 3
#define DEFAULT_VALUE (PIMValue_t)1

#define BUCKET_LOCKS_PER_CHUNK (1u << 3)
#define NR_BUCKET_LOCKS (BUCKET_LOCKS_PER_CHUNK * MAX_NUM_CHUNKS)
#define LOCKS_PER_CHUNK ((1u << 3) + 1)
#define LOCK_TABLE_LEN (MAX_NUM_CHUNKS * LOCKS_PER_CHUNK)

typedef enum KernelRet {
    exec_success,
    not_unique,
    insert_failure,
    count_mismatch,
} KernelRet;

typedef struct pimindex_dpu_args_t {
    uint32_t index_offs;
    union {
        uint32_t num_chunks;
        uint32_t kernel;
    };
    union {
        uint32_t num_buckets;
        uint32_t keys_offs;
    };
    union {
        uint32_t num_keys;
        KernelRet kret;
    };
} pimindex_dpu_args_t;

typedef enum HashScheme {
    single_hash,
    double_hash,
    stash,
} HashScheme;

typedef enum OpRet {
    entry_inserted,
    update_conflict,
    duplicate_key,
    bucket_full,
    stash_full,
} OpRet;

typedef enum elem_type_t {
    UINT32,
    UINT64,
    BUCKET
} elem_type_t;

typedef struct BucketHeader {
    uint16_t bitmap; /* [15:14] reserved, [13:0] bitmap */
    uint8_t fingerprints[ENTRIES_PER_BUCKET_PIM];
} BucketHeader;

typedef struct BucketEntry {
    uint32_t key;
    uint32_t val;
} BucketEntry;

typedef union Bucket {
    BucketEntry entries[2 + ENTRIES_PER_BUCKET_PIM];
    BucketHeader header;
} Bucket;

typedef struct ChunkHeader {
    uint8_t local_depth;
    uint8_t hash_scheme;
    uint16_t reserve;
    uint32_t cid;
} ChunkHeader;

typedef struct IndexFile {
    ChunkHeader chunk_headers[0];
} IndexFile;

typedef struct BucketLog {
    uint8_t mem[256];
} BucketLog;

typedef struct PtrLog {
    uint64_t head_ptr;
    uint64_t tail_ptr;
} PtrLog;

typedef struct VChunkLog {
    uint32_t cur_bucket_log;
    uint32_t cur_ptr_log;
    BucketLog bucket_entry;
    PtrLog ptr_entry[0];
} VChunkLog;

typedef struct CBLock {
    uint32_t tasklet_id : 8;
    uint32_t ref_count : 8;
    uint32_t version : 16;
} CBLock;

typedef struct VChunkHeader {
    uint32_t cid;
    uint32_t next_free_bucket;
    uint64_t free_list; /* TODO */
    uint32_t block_bitmap[0]; /* TODO */
} VChunkHeader;

#define DPU_PROFILE "sgXferEnable=true"
#define CC_BIN "./dpubin/dpucc"

#define ANSI_RED        "\033[31m"
#define ANSI_GREEN      "\033[32m"
#define ANSI_MAGENTA    "\033[35m"
#define ANSI_RESET      "\033[0m"

#define PRINT_INFO(fmt, ...)        fprintf(stdout, "%sINFO:       %s" fmt "\n", ANSI_GREEN, ANSI_RESET, ##__VA_ARGS__)
#define PRINT_WARNING(fmt, ...)     fprintf(stderr, "%sWARNING:    %s" fmt "\n", ANSI_MAGENTA, ANSI_RESET, ##__VA_ARGS__)
#define PRINT_ERROR(fmt, ...)       fprintf(stderr, "%sERROR:      %s" fmt "\n", ANSI_RED, ANSI_RESET, ##__VA_ARGS__)

#define PRINT_MSG(fmt, ...)         printf(fmt "\n", ##__VA_ARGS__)
#define PRINT_TOP_RULE              printf("%s===============%s\n", ANSI_GREEN, ANSI_RESET);

#endif
