#ifndef hash_h
#define hash_h

#include <stdint.h>

/* https://github.com/gcc-mirror/gcc/blob/master/libstdc++-v3/libsupc++/hash_bytes.cc */


inline uint64_t unaligned_load(const char *p) {
    uint64_t result;
    memcpy(&result, p, sizeof(result));
    return result;
}

/* Loads n bytes, where 1 <= n < 8. */
inline uint64_t load_bytes(const char *p, int n) {
    uint64_t result = 0;
    --n;
    do
        result = (result << 8) + (unsigned char)(p[n]);
    while (--n >= 0);
    return result;
}

inline uint64_t shift_mix(uint64_t v) { return v ^ (v >> 47); }

/* Implementation of Murmur hash for 64-bit size_t. */
inline uint64_t Hash_bytes(const void *ptr, uint64_t len, uint64_t seed) {
    static const uint64_t mul = (0xc6a4a793UL << 32UL) + 0x5bd1e995UL;
    const char *const buf = (const char *)(ptr);

    // Remove the bytes not divisible by the sizeof(uint64_t).  This
    // allows the main loop to process the data as 64-bit integers.
    const int len_aligned = len & ~0x7;
    const char *const end = buf + len_aligned;
    uint64_t hash = seed ^ (len * mul);
    for (const char *p = buf; p != end; p += 8) {
        const uint64_t data = shift_mix(unaligned_load(p) * mul) * mul;
        hash ^= data;
        hash *= mul;
    }
    if ((len & 0x7) != 0) {
        const uint64_t data = load_bytes(end, len & 0x7);
        hash ^= data;
        hash *= mul;
    }
    hash = shift_mix(hash) * mul;
    hash = shift_mix(hash);
    return hash;
}

inline uint64_t murmur(const void *_ptr, uint64_t _len, uint64_t _seed) {
    return Hash_bytes(_ptr, _len, _seed);
}

static uint64_t (*hash_funcs[1])(const void *key, uint64_t len, uint64_t seed) = {murmur};

static inline uint64_t h(const void *key, uint64_t len, uint64_t seed) {
    return hash_funcs[0](key, len, seed);
}

uint64_t hash(uint32_t key) {
    return h(&key, sizeof(uint32_t), 0xc70697UL);
}

#define get16bits(d) ((((uint32_t)(((const uint8_t *)(d))[1])) << 8) +(uint32_t)(((const uint8_t *)(d))[0]) )

uint32_t key_to_dpu_hash(uint32_t key) {
  int len = 4;
  uint8_t* data_;
  uint8_t data[4];
  data_ = data;
  *(uint32_t*)(data) = key;
  uint32_t hash = 4, tmp;
	int rem;

  rem = len & 3;
  len >>= 2;

  /* Main loop */
  for (;len > 0; len--) {
      hash  += get16bits (data);
      tmp    = (get16bits (data+2) << 11) ^ hash;
      hash   = (hash << 16) ^ tmp;
      data_  += 2*sizeof (uint16_t);
      hash  += hash >> 11;
  }

  /* Handle end cases */
  switch (rem) {
      case 3: hash += get16bits (data);
    hash ^= hash << 16;
    hash ^= data[sizeof (uint16_t)] << 18;
    hash += hash >> 11;
    break;
      case 2: hash += get16bits (data);
    hash ^= hash << 11;
    hash += hash >> 17;
    break;
      case 1: hash += *data;
    hash ^= hash << 10;
    hash += hash >> 1;
  }

  /* Force "avalanching" of final 127 bits */
  hash ^= hash << 3;
  hash += hash >> 5;
  hash ^= hash << 4;
  hash += hash >> 17;
  hash ^= hash << 25;
  hash += hash >> 6;

  return hash;

}

uint32_t key_to_tasklet_hash(uint32_t key) {
    key -= (key<<6);
    key ^= (key>>17);
    key -= (key<<9);
    key ^= (key<<4);
    key -= (key<<3);
    key ^= (key<<10);
    key ^= (key>>15);
    return key;
}

#endif  /* #ifndef pimindex_hash_h */
