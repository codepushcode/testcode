#include <defs.h>
#include <mram.h>
#include <alloc.h>
#include <barrier.h>
#include <stdint.h>
#include <stdio.h>
#include <mutex.h>
#include <mutex_pool.h>
#include <built_ins.h>
#include <string.h>
#include <stdlib.h>

#include "../include/ccdefs.h"
#include "../include/hash.h"

MUTEX_INIT(next_free_cid_mtx);
MUTEX_INIT(index_file_lock_mtx);
MUTEX_POOL_INIT(chunk_locks_mtx, 4);
MUTEX_POOL_INIT(bucket_locks_mtx, 4);
MUTEX_POOL_INIT(chunk_hdr_locks_mtx, 8);
MUTEX_POOL_INIT(chunk_bitmap_mtx, 2);
BARRIER_INIT(index_barrier, NR_TASKLETS);

__host struct pimindex_dpu_args_t dpu_args;


/* MRAM pointers */
char* index_file_head;
char* index_file_head1;
char* index_file_head2;
char* chunks_offset;
IndexFile* index_file;
IndexFile* index_file1;
IndexFile* index_file2;
uint32_t* schunk_ids;
VChunkLog* vchunk_log;
VChunkHeader** vchunk_headers;

/* WRAM pointers */
void *wr_pool;
void **wr_buffer;
void **wr_buffer2; /* TODO: single/per-tasklet */
void **wr_buffer3;
uint32_t* wr_chunk_bitmap;
uint8_t *wr_chunk_hdr_locks;
CBLock *wr_chunk_locks;
CBLock *wr_bucket_locks;
uint32_t* wr_hist;
PIMKey_t* wr_part_buffer;
uint8_t* wr_part_counter;

uint32_t prefix;
uint8_t global_depth;
uint32_t num_chunk_hdrs;
uint32_t num_schunks;
uint64_t next_free_chunk_id;
uint64_t index_file_lock; /* [63:32] unused, [31:] ptr, [30:] lock bit, [29:0] version */

const uint32_t index_file_lock_mask = (1u << 30);
const uint32_t mram_heap = (uint32_t)DPU_MRAM_HEAP_POINTER;


static inline uint32_t chunk_hdr_pos(uint64_t hash, uint8_t mask_bits) {
    /* TODO: 4-byte hash values */
    return (hash << 32) >> (64 - mask_bits);
}

static inline uint32_t chunk_hdr_ext_pos(uint64_t hash, uint8_t new_depth) {
    return hash << (30 + new_depth) >> 62;
}

static inline uint8_t fingerprint(uint64_t hash) {
    return hash >> 56;
}

static inline char* align_8B(char* ptr) {
    /* return ptr += ((8 - ((uint32_t)ptr % 8)) % 8); */
    uint32_t rem = (uint32_t)ptr % 8;
    return (rem == 0) ? (ptr) : (ptr + 8 - rem);
}

static inline char* align_bucket_size(char* ptr) {
    /* return ptr += ((BUCKET_SIZE - ((uint32_t)ptr % BUCKET_SIZE)) % BUCKET_SIZE); */
    uint32_t rem = (uint32_t)ptr % BUCKET_SIZE;
    return (rem == 0) ? (ptr) : (ptr + BUCKET_SIZE - rem);
}

/*static inline char* align_chunk_size(char* ptr) {
    uint32_t rem = (uint32_t)ptr % CHUNK_SIZE;
    return (rem == 0) ? (ptr) : (ptr + CHUNK_SIZE - rem);
}*/

static inline void* chunk_ptr(uint32_t cid) {
    return chunks_offset + cid * CHUNK_SIZE;
}

static inline bool try_acquire_index_file_lock() {
    mutex_lock(index_file_lock_mtx);
    uint32_t old_index_file_lock = (uint32_t) index_file_lock; /* TODO: atomic */
    if (old_index_file_lock & index_file_lock_mask) {
        mutex_unlock(index_file_lock_mtx);
        return false;
    }
    uint32_t new_index_file_lock = old_index_file_lock | index_file_lock_mask;
    index_file_lock = (uint64_t)new_index_file_lock;
    mutex_unlock(index_file_lock_mtx);
    return true;
}

static inline void acquire_index_file_lock() {
    while (!try_acquire_index_file_lock());
}

static inline void release_index_file_lock() {
    uint32_t new_index_file_lock = ((uint32_t )index_file_lock + 1) & 0xbfffffffu;
    uint64_t val = (uint64_t)new_index_file_lock;
    index_file_lock = val; /* TODO: lock to syncrinize with readers */
}

static inline uint32_t bucket_id(uint64_t hash) {
    /* return (hash << 8) >> 53; */
    return (hash << 8) >> 54;
}

static inline uint16_t is_bit_set(uint16_t bitmap, uint32_t slot) {
    return bitmap & (1u << ((ENTRIES_PER_BUCKET_PIM - 1) - slot));
}

static inline uint32_t next_free_slot(uint16_t bitmap) {
    uint32_t mask = ~((uint32_t)bitmap << 16);
    uint32_t slot;
    __builtin_clz_rr(slot, mask);
    return slot;
}

static inline uint16_t set_bitmap(uint16_t bitmap, uint32_t slot) {
    return bitmap | (1u << (15 - slot));
}

static inline void release_flip_index_file_lock() {
    uint32_t new_index_file_lock = ((uint32_t) index_file_lock + 1) & 0xbfffffffu;
    if (new_index_file_lock & 0x80000000) {
        new_index_file_lock &= 0x7FFFFFFF;
    }
    else {
        new_index_file_lock |= 0x80000000;
    }
    uint64_t val = (uint64_t) new_index_file_lock;
    index_file_lock = val;  /* TODO: lock to syncrinize with readers */
}

static inline bool try_acquire_chunk_hdr_lock(uint32_t pos) {
    mutex_pool_lock(&chunk_hdr_locks_mtx, pos);
    if (wr_chunk_hdr_locks[pos] == 1) {
        mutex_pool_unlock(&chunk_hdr_locks_mtx, pos);
        return false;
    }
    wr_chunk_hdr_locks[pos] = 1;
    mutex_pool_unlock(&chunk_hdr_locks_mtx, pos);
    return true;
}

static inline void acquire_chunk_hdr_lock(uint32_t pos) {
    while (!try_acquire_chunk_hdr_lock(pos));
}

static inline void release_chunk_hdr_lock(uint32_t pos) {
    mutex_pool_lock(&chunk_hdr_locks_mtx, pos);
    wr_chunk_hdr_locks[pos] = 0;
    mutex_pool_unlock(&chunk_hdr_locks_mtx, pos);
}

static inline bool is_locked(uint32_t* lock_val) {
    CBLock lock = *((CBLock*)lock_val);
    return lock.ref_count > 0;
}

static inline uint32_t get_chunk_lock_val(uint32_t cid) {
    mutex_pool_lock(&chunk_locks_mtx, cid);
    uint32_t* ptr = (uint32_t*) &wr_chunk_locks[cid];
    uint32_t lock_val = *ptr; /* TODO: atomic */
    mutex_pool_unlock(&chunk_locks_mtx, cid);
    return lock_val;
}

static inline bool try_acquire_chunk_lock(uint32_t cid, uint32_t tasklet_id) {
    /* separate mutexes for chunks and buckets to reduce false conflicts */
    mutex_pool_lock(&chunk_locks_mtx, cid); /* TODO: eager/lazy release */
    uint32_t* ptr = (uint32_t*) &wr_chunk_locks[cid];
    uint32_t old_lock_val = *ptr;
    mutex_pool_unlock(&chunk_locks_mtx, cid);

    CBLock old_lock = *((CBLock*) &old_lock_val);
    if ((old_lock.ref_count > 0) && (old_lock.tasklet_id != tasklet_id)) {
        return false;
    }

    CBLock new_lock = old_lock;
    new_lock.tasklet_id = tasklet_id;
    new_lock.ref_count++;
    uint32_t new_lock_val = *((uint32_t*) &new_lock);

    mutex_pool_lock(&chunk_locks_mtx, cid);
    ptr = (uint32_t*) &wr_chunk_locks[cid];
    if (*ptr != old_lock_val) {
        mutex_pool_unlock(&chunk_locks_mtx, cid);
        return false;
    }
    *ptr = new_lock_val;
    mutex_pool_unlock(&chunk_locks_mtx, cid);

    return true;
}

static inline void acquire_chunk_lock(uint32_t cid, uint32_t tasklet_id) {
    while (!try_acquire_chunk_lock(cid, tasklet_id));
}

static inline void release_chunk_lock(uint32_t cid) {
    mutex_pool_lock(&chunk_locks_mtx, cid); /* TODO: eager/lazy release */
    uint32_t* ptr = (uint32_t*) &wr_chunk_locks[cid];
    uint32_t lock_val = *ptr;
    mutex_pool_unlock(&chunk_locks_mtx, cid);

    CBLock lock = *((CBLock*) &lock_val);
    if (lock.ref_count > 0) {
        lock.ref_count--;
        lock.version++;

        uint32_t val = *((uint32_t*) &lock);
        mutex_pool_lock(&chunk_locks_mtx, cid);
        *ptr = val;
        mutex_pool_unlock(&chunk_locks_mtx, cid);
    }
}

static inline uint32_t bucket_lock_pos(uint32_t cid, uint32_t bid) {
    return (cid * BUCKET_LOCKS_PER_CHUNK) + (bid & (BUCKET_LOCKS_PER_CHUNK - 1));
}

static inline uint32_t get_bucket_lock_val(uint32_t pos) {
    mutex_pool_lock(&bucket_locks_mtx, pos);
    uint32_t* ptr = (uint32_t*) &wr_bucket_locks[pos];
    uint32_t lock_val = *ptr; /* TODO: atomic */
    mutex_pool_unlock(&bucket_locks_mtx, pos);
    return lock_val;
}

static inline bool try_acquire_bucket_lock(uint32_t pos, uint32_t tasklet_id) {
    mutex_pool_lock(&bucket_locks_mtx, pos); /* TODO: eager/lazy release */
    uint32_t* ptr = (uint32_t*) &wr_bucket_locks[pos];
    uint32_t old_lock_val = *ptr;
    mutex_pool_unlock(&bucket_locks_mtx, pos);

    CBLock old_lock = *((CBLock*) &old_lock_val);
    if ((old_lock.ref_count > 0) && (old_lock.tasklet_id != tasklet_id)) {
        return false;
    }

    CBLock new_lock = old_lock;
    new_lock.tasklet_id = tasklet_id;
    new_lock.ref_count++;
    uint32_t new_lock_val = *((uint32_t*) &new_lock);

    mutex_pool_lock(&bucket_locks_mtx, pos);
    ptr = (uint32_t*) &wr_bucket_locks[pos];
    if (*ptr != old_lock_val) {
        mutex_pool_unlock(&bucket_locks_mtx, pos);
        return false;
    }
    *ptr = new_lock_val;
    mutex_pool_unlock(&bucket_locks_mtx, pos);

    return true;
}

static inline void acquire_bucket_lock(uint32_t pos, uint32_t tasklet_id) {
    while (!try_acquire_bucket_lock(pos, tasklet_id));
}

static inline void release_bucket_lock(uint32_t pos) {
    mutex_pool_lock(&bucket_locks_mtx, pos); /* TODO: eager/lazy release */
    uint32_t* ptr = (uint32_t*) &wr_bucket_locks[pos];
    uint32_t lock_val = *ptr;
    mutex_pool_unlock(&bucket_locks_mtx, pos);

    CBLock lock = *((CBLock*) &lock_val);
    if (lock.ref_count > 0) {
        lock.ref_count--;
        lock.version++;

        uint32_t val = *((uint32_t*) &lock);
        mutex_pool_lock(&bucket_locks_mtx, pos);
        *ptr = val;
        mutex_pool_unlock(&bucket_locks_mtx, pos);
    }
}

uint32_t alloc_chunk() { /* TODO: mono- and multi-tasklet exec of alloc chunk */
GET_SLOT:
    ;
    uint32_t old_free_cid = (uint32_t)next_free_chunk_id; /* TODO: alignment of unsigned int for atomic rw */
    uint32_t byte_pos = old_free_cid / 32u;
    uint32_t old_val, new_val, bit_pos;
    byte_pos--;

    do {
        byte_pos++;
        mutex_pool_lock(&chunk_bitmap_mtx, byte_pos);
        old_val = wr_chunk_bitmap[byte_pos]; /* TODO: atomic unsigned int rw */
        mutex_pool_unlock(&chunk_bitmap_mtx, byte_pos);
    }
    while (old_val == 0);

    __builtin_clz_rr(bit_pos, old_val);
    new_val = old_val & ~(1u << (31 - bit_pos));

    mutex_pool_lock(&chunk_bitmap_mtx, byte_pos);
    if (old_val != wr_chunk_bitmap[byte_pos]) {
        mutex_pool_unlock(&chunk_bitmap_mtx, byte_pos);
        goto GET_SLOT;
    }
    wr_chunk_bitmap[byte_pos] = new_val;
    mutex_pool_unlock(&chunk_bitmap_mtx, byte_pos);

    uint32_t free_slot = byte_pos * 32 + bit_pos;
    uint32_t val = (uint64_t)free_slot + 1;
    next_free_chunk_id = val;

    return free_slot;
}

void alloc_chunks(uint32_t* cids) {
    if (next_free_chunk_id > (MAX_NUM_CHUNKS - 1)) {
        printf("No more chunks...\n"); /* TODO: ANSI color */
        exit(EXIT_FAILURE);
    }

    uint32_t cnt = 0;

    do {
        GET_SLOT:
        ;
        mutex_lock(next_free_cid_mtx);
        /* TODO: acquire the lock once and release after allocating chunks.
                 less likely that multiple tasklets are allocating chunks simultaneously.
                 trade-off between tasklets waiting and acquiring/releasing locks in each iteration */
        uint32_t old_free_cid = (uint32_t) next_free_chunk_id;
        mutex_unlock(next_free_cid_mtx);

        uint32_t byte_pos = old_free_cid / 32u;
        uint32_t bit_pos, old_val, new_val;
        byte_pos--;

        do {
            byte_pos++;
            mutex_pool_lock(&chunk_bitmap_mtx, byte_pos);
            /* TODO: acquire the lock once and release after allocating chunks.
                    less likely that multiple tasklets are allocating chunks simultaneously.
                    trade-off between tasklets waiting and acquiring/releasing locks in each iteration */
            old_val = wr_chunk_bitmap[byte_pos];
            mutex_pool_unlock(&chunk_bitmap_mtx, byte_pos);
        }
        while (old_val == 0);

        uint32_t bit_cnt;
        __builtin_cao_rr(bit_cnt, old_val);
        uint32_t bits = (bit_cnt < (4 - cnt)) ? bit_cnt : (4 - cnt);
        new_val = old_val;
        for (uint32_t i = 0; i < bits; i++) {
            __builtin_clz_rr(bit_pos, new_val);
            new_val = new_val & ~(1u << (31 - bit_pos));
            cids[cnt + i] = bit_pos;
        }

        mutex_pool_lock(&chunk_bitmap_mtx, byte_pos);
        if (old_val != wr_chunk_bitmap[byte_pos]) {
            mutex_pool_unlock(&chunk_bitmap_mtx, byte_pos);
            goto GET_SLOT;
        }
        wr_chunk_bitmap[byte_pos] = new_val;
        mutex_pool_unlock(&chunk_bitmap_mtx, byte_pos);

        for (uint32_t i = 0; i < bits; i++) {
            cids[cnt + i] += (byte_pos * 32);
        }
        cnt += bits;

        uint32_t last_free_slot = cids[cnt - 1];
        uint64_t val = (uint64_t)last_free_slot + 1;

        mutex_lock(next_free_cid_mtx);
        next_free_chunk_id = val;
        mutex_unlock(next_free_cid_mtx);

        if ((next_free_chunk_id > (MAX_NUM_CHUNKS - 1)) && (cnt < 4)) {
            printf("No more chunks\n"); /* TODO: ANSI color */
            exit(EXIT_FAILURE);
        }
    }
    while (cnt != 4);
}

void free_chunk(uint32_t cid) {
    uint32_t byte_pos = cid / 32;
    uint32_t bit_pos = cid % 32;

    bool swapped;
    uint32_t old_val, new_val;
    mutex_pool_lock(&chunk_bitmap_mtx, byte_pos);
    old_val = wr_chunk_bitmap[byte_pos];
    mutex_pool_unlock(&chunk_bitmap_mtx, byte_pos);

    do {
        new_val = old_val | (1u << (31 - bit_pos));
        mutex_pool_lock(&chunk_bitmap_mtx, byte_pos);
        if (wr_chunk_bitmap[byte_pos] == old_val) {
            wr_chunk_bitmap[byte_pos] = new_val;
            swapped = true;
        }
        else {
            swapped = false;
        }
        mutex_pool_unlock(&chunk_bitmap_mtx, byte_pos);
    }
    while (!swapped);

    mutex_lock(next_free_cid_mtx);
    uint32_t old_next_free_cid = (uint32_t) next_free_chunk_id;
    mutex_unlock(next_free_cid_mtx);

    do {
        if (old_next_free_cid < cid) {
            break;
        }
        if ((uint32_t)next_free_chunk_id == old_next_free_cid) {
            next_free_chunk_id = (uint64_t) cid;
            swapped = true;
        }
        else {
            swapped = false;
        }
    }
    while (!swapped);
}

void initialize_index(uint32_t tasklet_id) {

    if (tasklet_id == 0) {
        printf("Tasklet: %u\n", tasklet_id);
        mem_reset();

        wr_pool = (void*) mem_alloc(4 /* max. buffer types */ * 16 /* max. tasklets */ * WRAM_BUFFER_SIZE);
        wr_buffer = (void**) mem_alloc(NR_TASKLETS * sizeof(void*));
        wr_buffer2 = (void**) mem_alloc(NR_TASKLETS * sizeof(void*));
        wr_buffer3 = (void**) mem_alloc(NR_TASKLETS * sizeof(void*));
        wr_chunk_bitmap = (uint32_t*) mem_alloc(BITMAP_LEN * sizeof(uint32_t));
        wr_chunk_hdr_locks = (uint8_t*) mem_alloc(512 * sizeof(uint8_t)); /* TODO: use bits. memory/performance tradeoff */
        wr_chunk_locks = (CBLock*) mem_alloc(MAX_NUM_CHUNKS * sizeof(CBLock));
        wr_bucket_locks = (CBLock*) mem_alloc(NR_BUCKET_LOCKS * sizeof(CBLock));
    }
    barrier_wait(&index_barrier);

    for (uint32_t i = tasklet_id; i < BITMAP_LEN; i += NR_TASKLETS) {
        wr_chunk_bitmap[i] = (uint32_t)(-1); /* set all bits */
    }
    barrier_wait(&index_barrier); /* TODO */

    for (uint32_t i = tasklet_id; i < 512; i += NR_TASKLETS) {
        wr_chunk_hdr_locks[i] = 0;
    }

    for (uint32_t i = tasklet_id; i < MAX_NUM_CHUNKS; i += NR_TASKLETS) {
        uint32_t* ptr = (uint32_t*) &wr_chunk_locks[i];
        *ptr = 0u;
    }

    for (uint32_t i = tasklet_id; i < NR_BUCKET_LOCKS; i += NR_TASKLETS) {
        uint32_t* ptr = (uint32_t*) &wr_bucket_locks[i];
        *ptr = 0u;
    }

    /*wr_buffer[tasklet_id] = mem_alloc(WRAM_BUFFER_SIZE);
    wr_buffer2[tasklet_id] = mem_alloc(WRAM_BUFFER_SIZE);
    wr_buffer3[tasklet_id] = mem_alloc(WRAM_BUFFER_SIZE);*/

    wr_buffer[tasklet_id] = (char*)wr_pool + tasklet_id * WRAM_BUFFER_SIZE;
    wr_buffer2[tasklet_id] = (char*)wr_pool + (NR_TASKLETS + tasklet_id) * WRAM_BUFFER_SIZE;
    wr_buffer3[tasklet_id] = (char*)wr_pool + (2 * NR_TASKLETS + tasklet_id) * WRAM_BUFFER_SIZE;

    if (tasklet_id == 0) { /* TODO: multi-tasklet exec */

        num_chunk_hdrs = (1u << INIT_GLOBAL_DEPTH);
        wr_chunk_bitmap[0] = 0x7FFFFFFFu;
        next_free_chunk_id = 1;
        index_file_lock = 0;
        num_schunks = 0;

        schunk_ids = (uint32_t*) (mram_heap + dpu_args.index_offs);
        char* ptr = (char*)schunk_ids + 4 * MAX_NUM_SCHUNKS;
        vchunk_headers = (VChunkHeader**) mem_alloc((MAX_VCHUNK_DEGREE + 1) * sizeof(VChunkHeader*));

        VChunkHeader* wr_header = (VChunkHeader*) wr_buffer[tasklet_id];

        for (uint32_t i = 0; i <= MAX_VCHUNK_DEGREE; i++) {
            vchunk_headers[i] = (VChunkHeader*) align_8B(ptr);

            wr_header->cid = alloc_chunk();
            wr_header->next_free_bucket = 0;
            wr_header->free_list = 0;
            uint32_t block_bitmap_len = (i > 5) ? 1 : 1 << (6 - i);
            memset(wr_header->block_bitmap, 0xff, 4 * block_bitmap_len);
            mram_write(wr_header, (__mram_ptr void*) vchunk_headers[i], sizeof(VChunkHeader)); /* TODO: optimize */
            ptr = (char*)vchunk_headers[i] + 16 /* header */ + 4 * block_bitmap_len;
        }

        vchunk_log = (VChunkLog*) align_8B(ptr);
        ptr = (char*)vchunk_log + 1024; /* TODO */

        /* index_file_head1 = align_chunk_size(ptr); */
        index_file_head1 = align_bucket_size(ptr);
        index_file1 = (IndexFile*) (index_file_head1 + 64); /* TODO */
        index_file_head2 = index_file_head1 + CHUNK_SIZE;
        index_file2 = (IndexFile*) (index_file_head2 + 64);
        chunks_offset = index_file_head2 + CHUNK_SIZE;

        index_file_head = index_file_head1;
        index_file = index_file1;

        VChunkLog* wr_log = (VChunkLog*) wr_buffer[tasklet_id];
        wr_log->cur_bucket_log = 0;
        wr_log->cur_ptr_log = 0;
        mram_write(wr_log, (__mram_ptr void*) vchunk_log, sizeof(VChunkLog));

        for (uint32_t i = 0; i < num_chunk_hdrs; i++) {
            uint32_t cid = alloc_chunk(); /* TODO: store ids in WRAM and update all headers first */
            Bucket* chunk = (Bucket*) chunk_ptr(cid);

            Bucket* wr_buc = (Bucket*) wr_buffer[tasklet_id];
            for (uint32_t j = 0; j < BUCKETS_PER_CHUNK; j++) {
                wr_buc->header.bitmap = (uint16_t) 0xC000;
                mram_write(wr_buc, (__mram_ptr void*) &chunk[j], sizeof(Bucket));
            }

            /* TODO: optimize */
            ChunkHeader* wr_hdr = (ChunkHeader*) wr_buffer[tasklet_id];
            ChunkHeader* mr_hdr = &index_file->chunk_headers[i];
            wr_hdr->local_depth = INIT_GLOBAL_DEPTH;
            wr_hdr->hash_scheme = single_hash;
            wr_hdr->cid = cid;
            mram_write(wr_hdr, (__mram_ptr void*) mr_hdr, sizeof(ChunkHeader));
        }

        uint8_t* wram_index_file_head = (uint8_t*) wr_buffer[tasklet_id];
        wram_index_file_head[0] = INIT_GLOBAL_DEPTH;
        global_depth = INIT_GLOBAL_DEPTH;
        mram_write(wram_index_file_head, (__mram_ptr void*) index_file_head, 64); /* TODO: merge with the write of the first chunk */

    }
    barrier_wait(&index_barrier);
}

void expand_index_file(uint32_t hdr_pos, ChunkHeader* new_chunk_headers, uint32_t tasklet_id) {
    IndexFile* new_mram_index_file;
    IndexFile* old_mram_index_file = index_file;
    uint32_t lock = (uint32_t) index_file_lock;
    if (lock & 0x80000000u) {
        new_mram_index_file = (IndexFile*) index_file1;
        index_file_head = index_file_head1;
    }
    else {
        new_mram_index_file = (IndexFile*) index_file2;
        index_file_head = index_file_head2;
    }

    for (uint32_t i = 0; i < num_chunk_hdrs; i++) {
        /* TODO: optimize */
        ChunkHeader* mram_old_hdrs = &old_mram_index_file->chunk_headers[i];
        ChunkHeader* wram_old_hdrs = (ChunkHeader*) wr_buffer2[tasklet_id];
        mram_read((__mram_ptr const void*) mram_old_hdrs, wram_old_hdrs, sizeof(ChunkHeader));

        ChunkHeader* wram_new_hdrs = (ChunkHeader*) wr_buffer[tasklet_id];
        for (uint32_t k = 0; k < 4; k++) {
            wram_new_hdrs[k].local_depth = wram_old_hdrs->local_depth;
            wram_new_hdrs[k].hash_scheme = wram_old_hdrs->hash_scheme;
            wram_new_hdrs[k].cid = wram_old_hdrs->cid;
        }

        uint32_t j = (i << 2);
        ChunkHeader* mram_new_hdrs = &new_mram_index_file->chunk_headers[j];
        mram_write(wram_new_hdrs, (__mram_ptr void*) mram_new_hdrs, sizeof(ChunkHeader) * 4);
    }

    ChunkHeader* wram_new_hdrs = (ChunkHeader*) wr_buffer[tasklet_id];
    mram_read((__mram_ptr const void*) new_chunk_headers, wram_new_hdrs, sizeof(ChunkHeader) * 4);

    uint32_t jj = (hdr_pos << 2);
    ChunkHeader* mram_new_hdrs = &new_mram_index_file->chunk_headers[jj];
    mram_write(wram_new_hdrs, (__mram_ptr void*) mram_new_hdrs, sizeof(ChunkHeader) * 4);

    uint8_t* wram_index_file_head = (uint8_t*) wr_buffer[tasklet_id];
    wram_index_file_head[0] = global_depth + 2;
    mram_write(wram_index_file_head, (__mram_ptr void*) index_file_head, 8);

    global_depth += 2;
    num_chunk_hdrs = (1u << global_depth);
    index_file = new_mram_index_file;
}

void update_index_file(uint32_t hdr_pos, ChunkHeader* new_chunk_headers, uint8_t old_depth, uint32_t tasklet_id) {
    uint8_t depth_diff = global_depth - old_depth;
    uint32_t start_pos = hdr_pos >> depth_diff << depth_diff;
    uint32_t old_num_chunk_diff = 1u << depth_diff;
    uint32_t new_num_chunk_diff = old_num_chunk_diff >> 2;

    ChunkHeader* wram_old_chunk_hdrs = (ChunkHeader*) wr_buffer2[tasklet_id];
    ChunkHeader* wram_new_chunk_hdrs = (ChunkHeader*) wr_buffer[tasklet_id];
    mram_read((__mram_ptr const void*) new_chunk_headers, wram_new_chunk_hdrs, 4 * sizeof(ChunkHeader));

    uint32_t set_chunks = WRAM_BUFFER_SIZE / sizeof(ChunkHeader);
    for (uint32_t i = 0; i < 4; i++) {
        uint32_t pos = start_pos + new_num_chunk_diff * i;
        for (uint32_t j = pos; j < (pos + new_num_chunk_diff); j += set_chunks) {
            uint32_t chunks = ((j + set_chunks) < (pos + new_num_chunk_diff)) ? (set_chunks) : ((pos + new_num_chunk_diff) - j);

            for (uint32_t k = 0; k < chunks; k++) {
                wram_old_chunk_hdrs[k].cid = wram_new_chunk_hdrs[i].cid;
                wram_old_chunk_hdrs[k].hash_scheme = wram_new_chunk_hdrs[i].hash_scheme;
                wram_old_chunk_hdrs[k].local_depth = wram_new_chunk_hdrs[i].local_depth;
            }

            ChunkHeader* mram_old_chunk_hdrs = &index_file->chunk_headers[j];
            mram_write(wram_old_chunk_hdrs, (__mram_ptr void*) mram_old_chunk_hdrs, chunks * sizeof(ChunkHeader));
        }
    }
}

static inline bool single_hash_reassign_bucket_entries(Bucket* old_bucket, uint8_t new_depth, uint32_t* new_cids, uint32_t tasklet_id) {
    Bucket* wram_old_bucket = (Bucket*) wr_buffer2[tasklet_id]; /* pin in WRAM */
    mram_read((__mram_ptr const void*) old_bucket, wram_old_bucket, BUCKET_SIZE);

    uint32_t bid;
    uint64_t hash_val;
    uint32_t new_cid;
    BucketEntry* old_entry;
    for (uint32_t i = 0; i < ENTRIES_PER_BUCKET_PIM; i++) {
        if (is_bit_set(wram_old_bucket->header.bitmap, i)) {
            old_entry = &wram_old_bucket->entries[BUCKET_HEADER_SKIP + i];
            hash_val = hash(old_entry->key);
            bid = bucket_id(hash_val);
            new_cid = new_cids[chunk_hdr_ext_pos(hash_val, new_depth)];

            Bucket* new_chunk = (Bucket*) chunk_ptr(new_cid);
            Bucket* wram_new_bucket = (Bucket*) wr_buffer[tasklet_id];
            mram_read((__mram_ptr const void*) &new_chunk[bid], wram_new_bucket, sizeof(Bucket));
            uint32_t slot = next_free_slot(wram_new_bucket->header.bitmap);

            if (slot == (BUCKET_HEADER_SKIP + ENTRIES_PER_BUCKET_PIM)) {
                return false;
            }
            else {
                wram_new_bucket->entries[slot] = *old_entry;
                uint8_t fgprint = wram_old_bucket->header.fingerprints[i];
                wram_new_bucket->header.fingerprints[slot - 
                                                     BUCKET_HEADER_SKIP] = fgprint;
                wram_new_bucket->header.bitmap =
                                set_bitmap(wram_new_bucket->header.bitmap, slot);
                mram_write(wram_new_bucket,
                                (__mram_ptr void*) &new_chunk[bid], sizeof(Bucket));
            }

        }
    }
    return true;
}

ChunkHeader* split_chunk(uint32_t old_cid, uint8_t old_local_depth, uint32_t tasklet_id) {
    uint32_t new_cids[4];
    alloc_chunks(new_cids);
    ChunkHeader* new_hdrs = (ChunkHeader*) wr_buffer[tasklet_id];
    /*uint32_t* new_cids = (uint32_t*) cache;
    alloc_chunks(new_cids);
    ChunkHeader* new_hdrs = (ChunkHeader*) &new_cids[4];*/
    uint8_t new_depth = old_local_depth + 2;

    for (uint32_t i = 0; i < 4; i++) {
        new_hdrs[i].local_depth = new_depth;
        new_hdrs[i].hash_scheme = single_hash;
        new_hdrs[i].cid = new_cids[i];
    }

    ChunkHeader* mram_new_hdrs = &index_file->chunk_headers[512 + tasklet_id * 16]; /* TODO: modify */
    mram_write(new_hdrs, (__mram_ptr void*) mram_new_hdrs, sizeof(ChunkHeader) * 4);

    for (uint32_t i = 0; i < 4; i++) {
        uint32_t new_cid = new_cids[i];
        Bucket* new_chunk = (Bucket*) chunk_ptr(new_cid);
        Bucket* new_bucket = (Bucket*) wr_buffer[tasklet_id];

        for (uint32_t j = 0; j < BUCKETS_PER_CHUNK; j++) {
            new_bucket->header.bitmap = (uint16_t) 0xc000;
            mram_write(new_bucket, (__mram_ptr void*) &new_chunk[j], sizeof(Bucket));
        }
    }

    Bucket* old_chunk = (Bucket*) chunk_ptr(old_cid);
    for (uint32_t i = 0; i < BUCKETS_PER_CHUNK; i++) {
        Bucket* old_bucket = &old_chunk[i];
        if (!single_hash_reassign_bucket_entries(old_bucket, new_depth, new_cids, tasklet_id)) {
            ; /* TODO */
        }
    }

    return mram_new_hdrs;
}

static inline bool key_exists(Bucket* bucket, PIMKey_t key, uint8_t fgprint) {
    BucketHeader* header = &bucket->header;

    /* TODO: optimize */
    uint8_t cmp[ENTRIES_PER_BUCKET_PIM] = {0};
    for (uint32_t i = 0; i < ENTRIES_PER_BUCKET_PIM; i++) {
        cmp[i] = (header->fingerprints[i] == fgprint) ? 1 : 0;
    }

    for (uint32_t i = 0; i < ENTRIES_PER_BUCKET_PIM; i++) {
        if (cmp[i]) { /* TODO: use intrinsics */
            if (bucket->entries[BUCKET_HEADER_SKIP + i].key == key) {
                return true;
            }
        }
    }

    return false;
}

static inline void insert_bucket_entry(Bucket* bucket, PIMKey_t key, PIMValue_t val, uint8_t fgprint) {
    BucketHeader* buc_header = &bucket->header;
    uint32_t slot = next_free_slot(buc_header->bitmap);
    bucket->entries[slot].key = key;
    bucket->entries[slot].val = val;

    buc_header->fingerprints[slot - BUCKET_HEADER_SKIP] = fgprint;
    buc_header->bitmap = set_bitmap(buc_header->bitmap, slot);
}

OpRet strict_single_hash_insert(PIMKey_t key, PIMValue_t val, uint32_t cid, uint32_t bid,
                                uint8_t fgprint, uint8_t index_locked, uint32_t tasklet_id) {

    Bucket* chunk = (Bucket*) chunk_ptr(cid);
    Bucket* mram_bucket = &chunk[bid];
    Bucket* wram_bucket = (Bucket*) wr_buffer[tasklet_id];

    uint32_t blp = bucket_lock_pos(cid, bid);
    acquire_bucket_lock(blp, tasklet_id);
    mram_read((__mram_ptr const void*) mram_bucket, wram_bucket, BUCKET_SIZE);

    if (key_exists(wram_bucket, key, fgprint)) {
        release_bucket_lock(blp);
        release_chunk_lock(cid);
        if (index_locked) {
            release_index_file_lock();
        }

        return duplicate_key;
    }

    uint32_t bit_cnt;
    __builtin_cao_rr(bit_cnt, (uint32_t)wram_bucket->header.bitmap);
    if (bit_cnt == (BUCKET_HEADER_SKIP + ENTRIES_PER_BUCKET_PIM)) {
        /* wait for all other insertions in the chunk to complete */
        for (uint32_t i = 0; i < bid; i++) {
            uint32_t j = bucket_lock_pos(cid, i);
            acquire_bucket_lock(j, tasklet_id);
        }
        for (uint32_t i = (bid + 1); i < BUCKETS_PER_CHUNK; i++) {
            /* TODO: lock using "BUCKET_LOCKS_PER_CHUNK" instead of BUCKETS_PER_CHUNK */
            uint32_t j = bucket_lock_pos(cid, i);
            acquire_bucket_lock(j, tasklet_id);
        }

        return bucket_full;
    }
    else {
        release_chunk_lock(cid);
        if (index_locked) {
            release_index_file_lock();
        }

        insert_bucket_entry(wram_bucket, key, val, fgprint);
        mram_write(wram_bucket, (__mram_ptr void*) mram_bucket, BUCKET_SIZE);
        release_bucket_lock(blp);

        return entry_inserted;
    }
}

OpRet strict_insert(PIMKey_t key, PIMValue_t val, uint64_t hash, uint32_t tasklet_id) {
    OpRet ret;
GET_LOCKS:
    ;
    uint8_t index_locked = 1u;
    acquire_index_file_lock();

    uint32_t pos = chunk_hdr_pos(hash, global_depth);
    ChunkHeader* mram_hdr = &index_file->chunk_headers[pos];
    ChunkHeader* hdr = (ChunkHeader*)wr_buffer[tasklet_id];
    acquire_chunk_hdr_lock(pos);
    mram_read((__mram_ptr const void*) mram_hdr, hdr, sizeof(ChunkHeader)); /* TODO: optimize */
    release_chunk_hdr_lock(pos);

    uint32_t cid = hdr->cid;
    if (!try_acquire_chunk_lock(cid, tasklet_id)) {
        release_index_file_lock();
        goto GET_LOCKS;
    }

    uint8_t depth = hdr->local_depth;
    if (depth < global_depth) {
        release_index_file_lock();
        index_locked = 0u;
    }

    acquire_chunk_hdr_lock(pos);
    mram_read((__mram_ptr const void*) mram_hdr, hdr, sizeof(ChunkHeader)); /* TODO: optimize */
    release_chunk_hdr_lock(pos);

    /* validate */
    if (cid != hdr->cid) {
        release_chunk_lock(cid);
        if (index_locked) {
            release_index_file_lock();
        }
        goto GET_LOCKS; /* TODO: directly acquire new chunk lock if index was not locked */
    }

    uint32_t bid = bucket_id(hash);
    uint8_t fgprint = fingerprint(hash);
    ret = strict_single_hash_insert(key, val, cid, bid, fgprint, index_locked, tasklet_id);

    if (ret == bucket_full) {
        /* TODO */;
        ChunkHeader* new_chunk_headers = split_chunk(cid, depth, tasklet_id);

        if (index_locked) {
            for (uint32_t i = 13; /* cid after index init */ i < cid; i++) {
                acquire_chunk_lock(i, tasklet_id);
            }
            for (uint32_t i = (cid + 1); i < MAX_NUM_CHUNKS; i++) {
                acquire_chunk_lock(i, tasklet_id);
            }

            expand_index_file(pos, new_chunk_headers, tasklet_id);

            for (int i = (MAX_NUM_CHUNKS - 1); i >= ((int)cid + 1); i--) {
                release_chunk_lock(i);
            }
            for (int i = (cid - 1); i >= 13; i--) {
                release_chunk_lock(i);
            }
        }
        else {
            update_index_file(pos, new_chunk_headers, depth, tasklet_id);
        }

        for (int i = (BUCKETS_PER_CHUNK - 1); i >= ((int)bid + 1); i--) {
            uint32_t j = bucket_lock_pos(cid, i);
            release_bucket_lock(j);
        }
        for (int i = (bid - 1); i >= 0; i--) {
            uint32_t j = bucket_lock_pos(cid, i);
            release_bucket_lock(j);
        }

        uint32_t blp = bucket_lock_pos(cid, bid);
        release_bucket_lock(blp);
        release_chunk_lock(cid);

        if (index_locked) {
            release_flip_index_file_lock();
        }

        free_chunk(cid);

        goto GET_LOCKS;
    }
    else {
        return ret;
    }
}

OpRet optimistic_single_hash_insert(PIMKey_t key, PIMValue_t val, uint64_t hash,
                                    uint32_t old_cid, uint32_t old_chunk_lock_val,
                                    uint32_t old_index_file_lock, uint32_t tasklet_id) {

    uint32_t bid = bucket_id(hash);
    uint32_t buc_lock_pos = bucket_lock_pos(old_cid, bid);
    acquire_bucket_lock(buc_lock_pos, tasklet_id);

    // mutex_lock(index_file_lock_mtx);
    // uint32_t new_index_file_lock = (uint32_t)index_file_lock;
    // mutex_unlock(index_file_lock_mtx);

    // uint32_t pos = chunk_hdr_pos(hash, global_depth);
    // ChunkHeader* mram_header = &index_file->chunk_headers[pos];
    // ChunkHeader* header = (ChunkHeader*)wr_buffer[tasklet_id];
    // acquire_chunk_hdr_lock(pos);
    // mram_read((__mram_ptr const void*) mram_header, header, sizeof(ChunkHeader)); /* TODO: optimize */
    // release_chunk_hdr_lock(pos);

    // uint32_t new_cid = header->cid;
    // uint32_t new_chunk_lock_val = get_chunk_lock_val(new_cid);

    // /* validate */
    // if (old_chunk_lock_val != new_chunk_lock_val || old_cid != new_cid ||
    //         old_index_file_lock != new_index_file_lock) {
    //     release_bucket_lock(buc_lock_pos);
    //     return update_conflict;
    // }

    old_chunk_lock_val = old_chunk_lock_val + 0;
    old_index_file_lock = old_index_file_lock + 0;

    Bucket* chunk = (Bucket*) chunk_ptr(old_cid);
    Bucket* mram_bucket = &chunk[bid];
    Bucket* wram_bucket = (Bucket*) wr_buffer[tasklet_id];
    mram_read((__mram_ptr void const*) mram_bucket, wram_bucket, BUCKET_SIZE);

    uint8_t fgprint = fingerprint(hash);
    if (key_exists(wram_bucket, key, fgprint)) {
        release_bucket_lock(buc_lock_pos);
        return duplicate_key;
    }

    uint32_t bit_cnt;
    uint32_t buc_bitmap = (uint32_t) wram_bucket->header.bitmap;
    __builtin_cao_rr(bit_cnt, buc_bitmap);

    if (bit_cnt == (BUCKET_HEADER_SKIP + ENTRIES_PER_BUCKET_PIM)) {
        release_bucket_lock(buc_lock_pos);
        return bucket_full;
    }
    else {
        insert_bucket_entry(wram_bucket, key, val, fgprint);
        mram_write(wram_bucket, (__mram_ptr void*) mram_bucket, BUCKET_SIZE);
        release_bucket_lock(buc_lock_pos);
        return entry_inserted;
    }
}

OpRet optimistic_insert(PIMKey_t key, PIMValue_t val, uint64_t hash, uint32_t tasklet_id) {
    OpRet ret;
CHECK_LOCKS:
    ;
    mutex_lock(index_file_lock_mtx);
    uint32_t old_index_file_lock = (uint32_t)index_file_lock; /* TODO: atomic */
    mutex_unlock(index_file_lock_mtx);
    if (old_index_file_lock & index_file_lock_mask) {
        goto CHECK_LOCKS;
    }

    uint32_t pos = chunk_hdr_pos(hash, global_depth);
    ChunkHeader* mram_header = &index_file->chunk_headers[pos];
    ChunkHeader* header = (ChunkHeader*)wr_buffer[tasklet_id];
    acquire_chunk_hdr_lock(pos);
    mram_read((__mram_ptr const void*) mram_header, header, sizeof(ChunkHeader)); /* TODO: optimize */
    release_chunk_hdr_lock(pos);

    uint32_t cid = header->cid;
    uint32_t ch_lock_val = get_chunk_lock_val(cid);
    if (is_locked(&ch_lock_val)) {
        goto CHECK_LOCKS;
    }

    ret = optimistic_single_hash_insert(key, val, hash, cid, ch_lock_val, old_index_file_lock, tasklet_id);

    if (ret == update_conflict) {
        goto CHECK_LOCKS;
    }
    else if (ret == bucket_full) {
        return strict_insert(key, val, hash, tasklet_id); /* TODO: evaluate eagerly splitting vs optimistically retrying */
    }
    else {
        return ret;
    }
}

OpRet insert(PIMKey_t key, PIMValue_t val, uint32_t tasklet_id) {
    uint64_t hash_val = hash(key);
    return optimistic_insert(key, val, hash_val, tasklet_id);
}

PIMValue_t search_bucket(PIMKey_t key, uint8_t fgprint, Bucket* bucket,
                                uint32_t lock_pos, uint32_t tasklet_id) {
    PIMValue_t ret;
    uint32_t lock_val;
CHECK_LOCKS:
    ;
    lock_val = get_bucket_lock_val(lock_pos);
    if (is_locked(&lock_val)) {
        goto CHECK_LOCKS;
    }

    Bucket* mram_bucket = bucket;
    Bucket* wram_bucket = (Bucket*) wr_buffer[tasklet_id];
    mram_read((__mram_ptr void const*) mram_bucket, wram_bucket, BUCKET_SIZE);

    BucketHeader* bucket_header = &wram_bucket->header;

    /* TODO: optimize */
    uint8_t cmp[ENTRIES_PER_BUCKET_PIM] = {0};
    for (uint32_t i = 0; i < ENTRIES_PER_BUCKET_PIM; i++) {
        cmp[i] = (bucket_header->fingerprints[i] == fgprint) ? 1 : 0;
    }

    for (uint32_t i = 0; i < ENTRIES_PER_BUCKET_PIM; i++) {
        if (cmp[i]) {
            if (wram_bucket->entries[BUCKET_HEADER_SKIP + i].key == key) {
                ret = wram_bucket->entries[BUCKET_HEADER_SKIP + i].val;
                uint32_t lv = get_bucket_lock_val(lock_pos);
                if (lv != lock_val) {
                    goto CHECK_LOCKS;
                }
                return ret;
            }
        }
    }

    return (PIMValue_t)0;
}

PIMValue_t single_hash_search(PIMKey_t key, uint64_t hash, uint32_t cid, uint32_t tasklet_id) {
    uint8_t fgprint = fingerprint(hash);
    uint32_t bid = bucket_id(hash);
    uint32_t lock_pos = bucket_lock_pos(cid, bid);
    Bucket* chunk = (Bucket*) chunk_ptr(cid);
    Bucket* bucket = &chunk[bid];

    return search_bucket(key, fgprint, bucket, lock_pos, tasklet_id);
}

PIMValue_t search(PIMKey_t key, uint32_t tasklet_id) {
    /* TODO: mixed insertions and search */
    PIMValue_t ret;
    uint64_t hash_val = hash(key);
CHECK_LOCKS:
    ;
    mutex_lock(index_file_lock_mtx);
    uint32_t old_index_file_lock = (uint32_t)index_file_lock; /* TODO: atomic */
    mutex_unlock(index_file_lock_mtx);
    if (old_index_file_lock & index_file_lock_mask) {
        goto CHECK_LOCKS;
    }

    uint32_t pos = chunk_hdr_pos(hash_val, global_depth);
    ChunkHeader* mram_hdr = &index_file->chunk_headers[pos];
    ChunkHeader* hdr = (ChunkHeader*)wr_buffer[tasklet_id];
    acquire_chunk_hdr_lock(pos);
    mram_read((__mram_ptr const void*) mram_hdr, hdr, sizeof(ChunkHeader)); /* TODO: optimize */
    release_chunk_hdr_lock(pos);

    uint32_t cid = hdr->cid; /* TODO: atomic */

    ret = single_hash_search(key, hash_val, cid, tasklet_id);

    mutex_lock(index_file_lock_mtx);
    uint32_t lock = (uint32_t)index_file_lock; /* TODO: atomic */
    mutex_unlock(index_file_lock_mtx);
    if (lock != old_index_file_lock) {
        goto CHECK_LOCKS;
    }

    return ret;
}

int initialization_kernel() {
    uint32_t tasklet_id = me();
    initialize_index(tasklet_id);
    return 0;
}

int insert_kernel() {

    uint32_t tasklet_id = me();

    uint32_t inserted_keys = 0;
    for (uint32_t i = (tasklet_id + 1);
                  i <= dpu_args.num_keys;
                  i += NR_TASKLETS) {
        OpRet ret = insert(i, dpu_args.num_keys + i, tasklet_id);
        if (ret != entry_inserted) {
            if (ret == duplicate_key) {
                dpu_args.kret = not_unique;
            }
            else {
                dpu_args.kret = insert_failure;
            }
            exit(EXIT_FAILURE);
        }
        inserted_keys++;
    }

    // printf("Tasklet: %u | Inserts: %u\n", tasklet_id, inserted_keys);
    *((uint32_t*) wr_buffer2[tasklet_id]) = inserted_keys;
    barrier_wait(&index_barrier);
    if (tasklet_id == 0) {
        uint32_t num_keys = 0;
        for (uint32_t i = 0; i < NR_TASKLETS; i++) {
            num_keys += *((uint32_t*) wr_buffer2[i]);
        }
        // printf("dpu_args.num_keys %u - %u\n", dpu_args.num_keys, num_keys);
        if (num_keys == dpu_args.num_keys) {
            dpu_args.kret = exec_success;
        }
        else {
            dpu_args.kret = count_mismatch;
        }
    }

    return 0;
}

int search_kernel() {

    uint32_t tasklet_id = me();

    uint32_t found = 0;
    uint32_t not_found = 0;
    for (uint32_t i = (tasklet_id + 1);
                  i <= dpu_args.num_keys;
                  i += NR_TASKLETS) {
        PIMValue_t val = search(i, tasklet_id);
        if (val == (dpu_args.num_keys + i)) {
            found++;
        }
        else {
            not_found++;
        }
    }
    // printf("Tasklet: %u | Found: %u | Not found: %u\n", tasklet_id, found, not_found);

    *((uint32_t*) wr_buffer2[tasklet_id]) = found;
    *((uint32_t*) wr_buffer[tasklet_id]) = not_found;
    barrier_wait(&index_barrier);
    if (tasklet_id == 0) {
        uint32_t num_found = 0;
        uint32_t num_not_found = 0;
        for (uint32_t i = 0; i < NR_TASKLETS; i++) {
            num_found += *((uint32_t*) wr_buffer2[i]);
            num_not_found += *((uint32_t*) wr_buffer[i]);
        }
        if (num_not_found == 0 && num_found == dpu_args.num_keys) {
            dpu_args.kret = exec_success;
        }
        else {
            dpu_args.kret = count_mismatch;
        }
    }

    return 0;
}

int (*kernels[NR_KERNELS])() =
    {initialization_kernel, insert_kernel, search_kernel};

int main() {
    return kernels[dpu_args.kernel]();
}
