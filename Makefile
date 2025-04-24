BUILD_DIR ?= /home/muji8742/src/cc/build/dpubin
SRC_DIR := /home/muji8742/src/cc
DPU_DIR := ${SRC_DIR}/dpu
HOST_DIR := ${SRC_DIR}/host
COMMON_INCLUDES := ${SRC_DIR}/include

NUM_DPUS ?= 1
NUM_TASKLETS ?= 11

define conf_filename
	${BUILD_DIR}/../dpuconf/.NUM_DPUS_$(1)_NUM_TASKLETS_$(2).conf
endef
CONF := $(call conf_filename,${NUM_DPUS},${NUM_TASKLETS})

DPU_CC := ${BUILD_DIR}/dpucc
DPU_CC_SRC := ${DPU_DIR}/cc.c

.PHONY: all clean test

__dirs := $(shell mkdir -p ${BUILD_DIR})

COMMON_FLAGS := -Wall -Wextra -Werror -g -I${COMMON_INCLUDES}
DPU_FLAGS := ${COMMON_FLAGS} -O2 -DNR_TASKLETS=${NUM_TASKLETS}

all: ${DPU_CC}

${CONF}:
	$(RM) $(call conf_filename,*,*)
	touch $(CONF)

${DPU_CC}: ${DPU_CC_SRC} ${COMMON_INCLUDES} ${CONF}
	dpu-upmem-dpurte-clang ${DPU_FLAGS} -o $@ ${DPU_CC_SRC}

clean:
	$(RM) ${DPU_CC}

test: ${DPU_CC}
	dpu-lldb -f ${BIN}
