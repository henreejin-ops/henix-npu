#ifndef HENIX_NPU_H
#define HENIX_NPU_H

#include "hw/core/sysbus.h"

/* Device name */
#define TYPE_HENIX_NPU "henix-npu"
OBJECT_DECLARE_SIMPLE_TYPE(HenixNPUState, HENIX_NPU)

/* MMIO layout */
#define HENIX_NPU_MMIO_SIZE        0x10000
#define HENIX_NPU_CMD_SRAM_SIZE    0x1000

/* Register map */
#define HENIX_NPU_REG_CMD_HEAD     0x1000  /* RO */
#define HENIX_NPU_REG_CMD_TAIL     0x1004  /* RW */
#define HENIX_NPU_REG_CMD_DOORBELL 0x1008  /* WO */
#define HENIX_NPU_REG_CMD_STATUS   0x100C  /* RO */
#define HENIX_NPU_REG_IRQ_STATUS   0x1010  /* RO */
#define HENIX_NPU_REG_IRQ_ENABLE   0x1014  /* RW */
#define HENIX_NPU_REG_COMPLETED_SEQ 0x1018 /* RO */
#define HENIX_NPU_REG_IRQ_ACK      0x101C  /* WO */

/* Command format */
#define HENIX_NPU_CMD_SIZE         512
#define HENIX_NPU_CMD_DEPTH        (HENIX_NPU_CMD_SRAM_SIZE / HENIX_NPU_CMD_SIZE)

/* Opcodes */
enum {
    HENIX_NPU_CMD_NOP     = 0,
    HENIX_NPU_CMD_COMPUTE = 1,
    HENIX_NPU_CMD_BARRIER = 2,
};

typedef struct HenixNPUCmd {
    uint32_t opcode;
    uint32_t seq;
    uint64_t arg0;
    uint64_t arg1;
    uint64_t arg2;
} HenixNPUCmd;

#endif /* HENIX_NPU_H */