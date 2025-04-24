#ifndef cc_hpp_
#define cc_hpp_

#include <iostream>
#include <random>
#include <map>
#include <fstream>
#include <cassert>
#include <chrono>

#include "ccdefs.h"

#include <dpu>
#include <dpu_log.h>


struct sg_partition_xfer_args_t {
    uint32_t* num_partitions;
    uint32_t** partition_sizes;
    PIMKey_t*** partition_ptrs;
};

bool sg_partition_func(struct sg_block_info* cpu_buffer, uint32_t dpuid, uint32_t part, void* params) {
    sg_partition_xfer_args_t* sg_params = (sg_partition_xfer_args_t*) params;
    uint32_t* sg_parts = sg_params->num_partitions;
    uint32_t** sg_part_sizes = sg_params->partition_sizes;
    PIMKey_t*** sg_part_ptrs = sg_params->partition_ptrs;

    if (part >= sg_parts[dpuid]) { /* number of partitions on the DPU exceeded */
        return false;
    }

    cpu_buffer->addr = (uint8_t*) sg_part_ptrs[dpuid][part];
    cpu_buffer->length = sg_part_sizes[dpuid][part] * KEY_SIZE;

    return true;
}

void* multidim_malloc(uint32_t rows, std::vector<std::vector<PIMKey_t*>*>& ptrs) {
    void** matrix = (void**) malloc(rows * sizeof(void*));
    for (uint32_t i = 0; i < rows; i++) {
        matrix[i] = ptrs[i]->data();
    }

    return matrix;
}

void randomize_keys(PIMKey_t* workload, uint32_t len) {
  srand(time(nullptr));
  for (uint32_t i = 0; i < 2 * len; i++) {
    int pos = rand() % len;
    PIMKey_t tmp = workload[pos];
    workload[pos] = workload[0];
    workload[0] = tmp;
  }
}

inline uint32_t get_type_size(elem_type_t type) {
    switch(type) {
        case UINT32:
            return sizeof(uint32_t);
        case UINT64:
            return sizeof(uint64_t);
        case BUCKET:
            return sizeof(Bucket);
        default:
            PRINT_ERROR("Type error");
            std::exit(EXIT_FAILURE);
    }
}

struct mram_heap_obj_t {
    mram_heap_obj_t() {
        block_sizes.resize(NR_DPUS, 0);
    }

    uint32_t offset;
    uint32_t max_block_size;
    std::vector<uint32_t> block_sizes;
    elem_type_t elem_type;
    uint32_t elem_size;
    std::string name;
};

struct mram_heap_t {
    std::vector<mram_heap_obj_t*> objs;
};

struct mram_mem_mgr_t {
    mram_mem_mgr_t() {
        heap_ = new mram_heap_t();
        offsets_.push_back(0);
        offsets_.push_back((64 * MiB));
        slots_.push_back(std::make_pair(true, nullptr));
    }

    ~mram_mem_mgr_t() {
        /* TODO */
    }

    mram_heap_obj_t* alloc_block(const std::string &name,
        std::vector<uint32_t>& block_sizes, uint32_t max_block_size,
            uint32_t align_size, elem_type_t type) {

        assert(align_size != 0);
        max_block_size += ((8 - (max_block_size % 8)) % 8); /* make block size 8-byte aligned */

        mram_heap_obj_t* new_obj = new mram_heap_obj_t();
        uint32_t offs = this->get_slot(new_obj, max_block_size, align_size);
        heap_->objs.push_back(new_obj);
        auto &obj = heap_->objs.back();

        obj->offset = offs;
        obj->max_block_size = max_block_size; /* TODO: unspecified max. block size */
        obj->elem_type = type;
        obj->elem_size = get_type_size(type);
        obj->name.assign(name);

        assert(block_sizes.size() == NR_DPUS);
        for (auto i = 0; i < NR_DPUS; i++) {
            if (block_sizes[i] > max_block_size) {
                PRINT_ERROR("MRAM block size error");
                std::exit(EXIT_FAILURE);
            }
            else {
                obj->block_sizes[i] = block_sizes[i];
            }
        }
        /* std::copy(block_sizes.begin(), block_sizes.end(), std::back_inserter(obj->block_sizes)); */

        return obj;
    }

    uint32_t get_slot(mram_heap_obj_t* obj, uint32_t max_block_size, uint32_t align_size) {
        /*TODO: case for unspecified max. block size */

        uint32_t init_rem_free_block = 64 * MiB;
        uint32_t init_offs = (uint32_t)(-1);
        uint32_t actual_offs = (uint32_t)(-1);
        uint32_t offs_pos = (uint32_t)(-1);

        for (std::size_t pos = 0; pos < (offsets_.size() - 1); pos++) {
            if (slots_[pos].first) { /* free slot */
                uint32_t offs_a = offsets_[pos];
                uint32_t bytes_rem = offs_a % align_size;
                uint32_t offs_b = offs_a + ((align_size - bytes_rem) % align_size);
                uint32_t free_block_size = offsets_[pos + 1] - offs_b;
                uint32_t actual_rem_free_block_size = free_block_size - max_block_size;

                if (actual_rem_free_block_size > 0) { /* TODO: check for equality */
                    if (actual_rem_free_block_size < init_rem_free_block) {
                        init_rem_free_block = actual_rem_free_block_size;
                        init_offs = offs_a;
                        actual_offs = offs_b;
                        offs_pos = pos;
                    }
                }
            }
        }

        if (actual_offs == ((uint32_t)(-1))) {
            PRINT_ERROR("MRAM block allocation error");
            std::exit(EXIT_FAILURE);
        }
        else {
            offsets_.insert(offsets_.begin() + offs_pos + 1, actual_offs + max_block_size);
            slots_.insert(slots_.begin() + offs_pos + 1, std::make_pair(true, nullptr));

            if (init_offs == actual_offs) {
                assert(slots_[offs_pos].first);
                slots_[offs_pos].first = false;
                slots_[offs_pos].second = obj;
            }
            else {
                offsets_.insert(offsets_.begin() + offs_pos + 1, actual_offs);
                slots_.insert(slots_.begin() + offs_pos + 1, std::make_pair(false, obj));
            }
        }

        return actual_offs;
    }

    mram_heap_obj_t* get_block(std::string &name) {
        for (auto &obj : heap_->objs) {
            if (obj->name == name) {
                return obj;
            }
        }
        return nullptr;
    }

    void free_block(std::string &name) {
        uint32_t idx = (uint32_t)(-1);
        mram_heap_obj_t *obj = NULL;

        for (std::size_t i = 0; i < heap_->objs.size(); i++) {
            if (name == heap_->objs.at(i)->name) {
                obj = heap_->objs.at(i);
                idx = i;
                break;
            }
        }

        if (!obj) {
            print_mram_info();
            PRINT_ERROR("%s not found", name.c_str());
            std::exit(EXIT_FAILURE);
        }

        uint32_t offs = obj->offset;
        uint32_t pos = (uint32_t)(-1);

        for (std::size_t p = 0; p < (offsets_.size() - 1); p++) {
            if (offsets_[p] == offs) {
                pos = p;
                break;
            }
        }

        if (pos == (uint32_t)(-1)) {
            PRINT_ERROR("MRAM heap item %u not found", pos);
            std::exit(EXIT_FAILURE);
        }

        if (offs != offsets_[pos]) {
            PRINT_ERROR("MRAM offset error: %u != %u | %s", offs, offsets_[pos], obj->name.c_str());
            std::exit(EXIT_FAILURE);
        }

        if ((offs + obj->max_block_size) != offsets_[pos + 1]) {
            PRINT_ERROR("MRAM offset error: (%u + %u) != %u | %s", offs, obj->max_block_size, offsets_[pos + 1], obj->name.c_str());
            std::exit(EXIT_FAILURE);
        }

        bool prev_free;
        bool post_free;

        if (pos != 0) {
            prev_free = slots_[pos - 1].first;
        }
        else {
            prev_free = false;
        }

        if ((std::size_t)pos != (offsets_.size() - 2)) {
            post_free = slots_[pos + 1].first;
        }
        else { /* the last offset */
            post_free = false;
        }

        if ((prev_free == true) && (post_free == true)) {
            offsets_.erase(offsets_.begin() + pos);
            offsets_.erase(offsets_.begin() + pos + 1);

            slots_.erase(slots_.begin() + pos);
            slots_.erase(slots_.begin() + pos + 1);
        }
        else if ((prev_free == true) && (post_free == false)) {
            offsets_.erase(offsets_.begin() + pos);

            slots_.erase(slots_.begin() + pos);
        }
        else if ((prev_free == false) && (post_free == true)) {
            offsets_.erase(offsets_.begin() + pos + 1);

            slots_.erase(slots_.begin() + pos);
        }
        else if ((prev_free == false) && (post_free == false)) {
            slots_[pos].first = true;
            slots_[pos].second = nullptr;
        }

        delete obj;
        heap_->objs.erase(heap_->objs.begin() + pos);
    }

    void print_mram_info() {
        PRINT_MSG("Print MRAM info...");
        for (std::size_t pos = 0; pos < (offsets_.size() - 1); pos++) {
            if (slots_[pos].first) {
                PRINT_MSG("Free slot: [%u, %u) %.*f KiB", offsets_[pos], offsets_[pos + 1], 2, (offsets_[pos + 1] - offsets_[pos]) / (float)KiB);
            }
            else {
                mram_heap_obj_t *obj = slots_[pos].second;
                PRINT_MSG("Used slot: [%u, %u) %.*f KiB | %s", offsets_[pos], offsets_[pos + 1], 2, (offsets_[pos + 1] - offsets_[pos]) / (float)KiB, obj->name.c_str());

                if (obj->offset != offsets_[pos]) {
                    PRINT_ERROR("MRAM offset error: %u != %u | %s", obj->offset, offsets_[pos], obj->name.c_str());
                    std::exit(EXIT_FAILURE);
                }

                if ((obj->offset + obj->max_block_size) != offsets_[pos + 1]) {
                    PRINT_ERROR("MRAM offset error: (%u + %u) != %u | %s", obj->offset, obj->max_block_size, offsets_[pos + 1], obj->name.c_str());
                    std::exit(EXIT_FAILURE);
                }
            }
        }
    }

    mram_heap_t* heap_;
    std::vector<uint32_t> offsets_;
    std::vector<std::pair<bool, mram_heap_obj_t*>> slots_;
};

using time_val = std::chrono::_V2::steady_clock::time_point;

struct event {
    std::vector<time_val> starts;
    std::vector<time_val> stops;
    std::string name;
};

struct timer {
    void start(const std::string &name) {
        if (timing || !cur_event.empty()) {
            PRINT_WARNING("There is an ongoing timing\n");
        }
        else if (events.find(name) != events.end()) {
            auto &e = events[name];
            e.starts.push_back({std::chrono::steady_clock::now()});
            timing = true;
            cur_event = name;
        }
        else {
            event e;
            e.name = name;
            e.starts.push_back({std::chrono::steady_clock::now()});
            events.emplace(std::piecewise_construct, std::forward_as_tuple(name), std::forward_as_tuple(e));
            timing = true;
            cur_event = name;

            events_seq.push_back(name);
        }
    }

    void stop() {
        if (!timing) {
            PRINT_WARNING("Timer was not started\n");
        }
        else {
            auto &e = events[cur_event];
            e.stops.push_back({std::chrono::steady_clock::now()});
            timing = false;
            cur_event = "";
        }
    }

    void print() {
        for (auto &n : events_seq) {
            auto &e = events.find(n)->second;
            assert(e.starts.size() == e.stops.size());
            uint64_t total = 0;
            for (std::size_t t = 0; t < e.starts.size(); t++) {
                auto d = std::chrono::duration_cast<std::chrono::microseconds>(e.stops[t] - e.starts[t]).count();
                total += d;
            }
            PRINT_INFO("%s: %f ms", e.name.c_str(), (total / (e.starts.size() * 1000.0)));
        }
    }

    void print_to_csv(const std::string &f, const std::string &mark, bool append = true) {
        std::ofstream ofs;
        if (append) {
            ofs.open(f, std::ios_base::app);
        }
        else {
            ofs.open(f);
        }

        if (!ofs) {
            PRINT_WARNING("Cannot open CSV file\n");
        }
        else {
            auto iter = events.begin();
            for (std::size_t t = 0; t < iter->second.starts.size(); t++) {
                /* assuming all events were measured the same number of times */
                for (auto &n : events_seq) {
                    auto &e = events.find(n)->second;
                    assert(e.starts.size() == e.stops.size());
                    auto d = std::chrono::duration_cast<std::chrono::microseconds>(e.stops[t] - e.starts[t]).count();
                    ofs << (d / 1000.0) << ",";
                }
                ofs << mark << "\n";
            }
            ofs.flush();
        }

        ofs.close();
    }

private:
    std::map<std::string, event> events;
    std::vector<std::string> events_seq;
    bool timing = false;
    std::string cur_event;
};

#endif
