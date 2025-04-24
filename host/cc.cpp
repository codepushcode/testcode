#include "cc.hpp"

// #define PRINT_DPU_LOGS

int main(int argc, char* argv[]) {

    try {
        /* allocate DPUs and load binary */
        timer t;
        bool validation;
        uint32_t num_dpus, dpuid;
        struct dpu_set_t dpu_set, dpu;

        DPU_ASSERT(dpu_alloc(NR_DPUS, DPU_PROFILE, &dpu_set));
        DPU_ASSERT(dpu_get_nr_dpus(dpu_set, &num_dpus));
        assert(num_dpus == NR_DPUS);
        DPU_ASSERT(dpu_load(dpu_set, CC_BIN, NULL));

        mram_mem_mgr_t *mram_mgr = new mram_mem_mgr_t();
        std::vector<uint32_t> chunk_sizes(NR_DPUS, CHUNK_SIZE);
        std::vector<mram_heap_obj_t*> chunk_blocks(MAX_NUM_CHUNKS);
        std::vector<pimindex_dpu_args_t> dpu_params(NR_DPUS);
        std::vector<uint32_t>* zeros =
            new std::vector<uint32_t>(((63 * MiB) / sizeof(uint32_t)), 0);

        PRINT_INFO("CC");
        PRINT_MSG("DPUs: %u", NR_DPUS);
        PRINT_MSG("Tasklets: %u", NR_TASKLETS);
        PRINT_MSG("Keys: %u", NR_OPERATIONS);

        /* zero out MRAM in all DPUs */
        PRINT_MSG("Zero out MRAM of all DPUs...");
        DPU_ASSERT(dpu_broadcast_to(dpu_set, DPU_MRAM_HEAP_POINTER_NAME,
                                0, zeros->data(), 63 * MiB, DPU_XFER_DEFAULT));

        /* allocate max. hash index chunks in MRAM */
        PRINT_MSG("Allocate max. hash index chunks in MRAM...");
        for (uint32_t i = 0; i < MAX_NUM_CHUNKS; i++) {
            /* TODO: alloc vchunks, schunks, metadata */
            chunk_blocks[i] =
                mram_mgr->alloc_block(("HT Chunk " + std::to_string(i)),
                                            chunk_sizes, CHUNK_SIZE, 8, BUCKET);
        }

        // mram_mgr->print_mram_info();

        /* transfer hash index initialization parameters to DPUs */
        PRINT_MSG("Transfer hash index initialization parameters to DPUs...");
        DPU_FOREACH(dpu_set, dpu, dpuid) {
            dpu_params[dpuid].index_offs = chunk_blocks[0]->offset;
            dpu_params[dpuid].kernel = 0;
            dpu_params[dpuid].keys_offs = 0;
            dpu_params[dpuid].num_keys = 0;
            DPU_ASSERT(dpu_prepare_xfer(dpu, &dpu_params[dpuid]));
        }
        DPU_ASSERT(dpu_push_xfer(dpu_set, DPU_XFER_TO_DPU,
                "dpu_args", 0, sizeof(pimindex_dpu_args_t), DPU_XFER_DEFAULT));

        /* launch the index initialization kernel */
        PRINT_MSG("Executing the index initialization kernel on DPUs...");
        t.start("init. kernel");
        DPU_ASSERT(dpu_launch(dpu_set, DPU_SYNCHRONOUS));
        t.stop();

#ifdef PRINT_DPU_LOGS
        /* dump DPU logs */
        PRINT_MSG("Dump DPU logs...");
        DPU_FOREACH(dpu_set, dpu, dpuid) {
            DPU_ASSERT(dpu_log_read(dpu, stdout));
        }
#endif /* PRINT_DPU_LOGS */

        /* transfer insert parameters to DPUs */
        PRINT_MSG("Transfer insert parameters to DPUs...");
        DPU_FOREACH(dpu_set, dpu, dpuid) {
            dpu_params[dpuid].kernel = 1;
            dpu_params[dpuid].keys_offs = MAX_MRAM_SIZE;
            dpu_params[dpuid].num_keys = NR_OPERATIONS;
            DPU_ASSERT(dpu_prepare_xfer(dpu, &dpu_params[dpuid]));
        }
        DPU_ASSERT(dpu_push_xfer(dpu_set, DPU_XFER_TO_DPU,
            "dpu_args", 0, sizeof(pimindex_dpu_args_t), DPU_XFER_DEFAULT));

        /* launch the insert kernel */
        PRINT_MSG("Executing the insert kernel on DPUs...");
        t.start("insert kernel");
        DPU_ASSERT(dpu_launch(dpu_set, DPU_SYNCHRONOUS));
        t.stop();

#ifdef PRINT_DPU_LOGS
        /* dump DPU logs */
        PRINT_MSG("Dump DPU logs...");
        DPU_FOREACH(dpu_set, dpu, dpuid) {
            DPU_ASSERT(dpu_log_read(dpu, stdout));
        }
#endif /* PRINT_DPU_LOGS */

        /* transfer insert validation parameters to CPU */
        PRINT_MSG("Transfer insert validation parameters to CPU...");
        DPU_FOREACH(dpu_set, dpu, dpuid) {
            DPU_ASSERT(dpu_prepare_xfer(dpu, &dpu_params[dpuid]));
        }
        DPU_ASSERT(dpu_push_xfer(dpu_set, DPU_XFER_FROM_DPU,
            "dpu_args", 0, sizeof(pimindex_dpu_args_t), DPU_XFER_DEFAULT));

        validation = true;
        for (uint32_t dpuid = 0; dpuid < NR_DPUS; dpuid++) {
            if (dpu_params[dpuid].kret != exec_success) {
                validation = false;
                break;
            }
        }
        if (validation) {
            PRINT_INFO("Insertion correct...");
        }
        else {
            PRINT_ERROR("Insertion not correct...");
        }

        /* transfer search parameters to DPUs */
        PRINT_MSG("Transfer search parameters to DPUs...");
        DPU_FOREACH(dpu_set, dpu, dpuid) {
            dpu_params[dpuid].kernel = 2;
            dpu_params[dpuid].keys_offs = MAX_MRAM_SIZE;
            dpu_params[dpuid].num_keys = NR_OPERATIONS;
            DPU_ASSERT(dpu_prepare_xfer(dpu, &dpu_params[dpuid]));
        }
        DPU_ASSERT(dpu_push_xfer(dpu_set, DPU_XFER_TO_DPU,
            "dpu_args", 0, sizeof(pimindex_dpu_args_t), DPU_XFER_DEFAULT));

        /* launch the search kernel */
        PRINT_MSG("Executing the search kernel on DPUs...");
        t.start("search kernel");
        DPU_ASSERT(dpu_launch(dpu_set, DPU_SYNCHRONOUS));
        t.stop();

#ifdef PRINT_DPU_LOGS
        /* dump DPU logs */
        PRINT_MSG("Dump DPU logs...");
        DPU_FOREACH(dpu_set, dpu, dpuid) {
            DPU_ASSERT(dpu_log_read(dpu, stdout));
        }
#endif /* PRINT_DPU_LOGS */

        /* transfer search validation parameters to CPU */
        PRINT_MSG("Transfer search validation parameters to CPU...");
        DPU_FOREACH(dpu_set, dpu, dpuid) {
            DPU_ASSERT(dpu_prepare_xfer(dpu, &dpu_params[dpuid]));
        }
        DPU_ASSERT(dpu_push_xfer(dpu_set, DPU_XFER_FROM_DPU,
            "dpu_args", 0, sizeof(pimindex_dpu_args_t), DPU_XFER_DEFAULT));

        validation = true;
        for (uint32_t dpuid = 0; dpuid < NR_DPUS; dpuid++) {
            if (dpu_params[dpuid].kret != exec_success) {
                validation = false;
                break;
            }
        }
        if (validation) {
            PRINT_INFO("Search correct...");
        }
        else {
            PRINT_ERROR("Search not correct...");
        }

        /* free DPUs */
        PRINT_MSG("Free DPUs...");
        DPU_ASSERT(dpu_free(dpu_set));

        delete mram_mgr;

        // t.print();
    }
    catch (const dpu::DpuError &e) {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}
