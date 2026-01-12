/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Henix NPU Command & Contract Header
 *
 * This header defines the **hardware–software contract**
 * shared by:
 *   - Userspace application
 *   - Kernel driver
 *   - QEMU Henix NPU device
 *
 * Rules:
 *  - Fixed command slot size: 512 bytes
 *  - Fixed common header: { opcode, seq }
 *  - Driver is command-opaque
 *  - Device interprets opcode + payload
 */

#ifndef __HENIX_NPU_CONTRACT_H__
#define __HENIX_NPU_CONTRACT_H__

#include <stdint.h>

/* ============================================================
 * Constants
 * ============================================================
 */

#define HENIX_CMD_SLOT_SIZE        512
#define HENIX_CMD_HEADER_SIZE      8   /* opcode + seq */
#define HENIX_CMD_PAYLOAD_SIZE     (HENIX_CMD_SLOT_SIZE - HENIX_CMD_HEADER_SIZE)

/* ============================================================
 * Opcode definitions
 * ============================================================
 */

#define HENIX_CMD_NOP              0x00
#define HENIX_CMD_MEMCPY           0x01
#define HENIX_CMD_BARRIER          0x02
#define HENIX_CMD_MATMUL           0x03

/* future expansion */
#define HENIX_CMD_RESERVED_MAX     0xFF

/* ============================================================
 * Common command header
 * ============================================================
 *
 * This header MUST be the first fields of every command.
 */

struct henix_cmd_hdr {
    uint32_t opcode;   /* HENIX_CMD_* */
    uint32_t seq;      /* monotonically increasing sequence id */
};

/* ============================================================
 * NOP command (no-op)
 * ============================================================
 */

struct henix_cmd_nop {
    struct henix_cmd_hdr hdr;
    uint8_t payload[HENIX_CMD_PAYLOAD_SIZE];
};

/* ============================================================
 * MEMCPY command
 * ============================================================
 *
 * Semantics:
 *  - Copy `len` bytes
 *  - From buffer_table[src_buf]
 *  - To   buffer_table[dst_buf]
 */

struct henix_cmd_memcpy {
    struct henix_cmd_hdr hdr;

    uint32_t src_buf;   /* buffer table index */
    uint32_t dst_buf;   /* buffer table index */
    uint32_t len;       /* bytes to copy */

    uint8_t  reserved[HENIX_CMD_PAYLOAD_SIZE - 12];
};

/* ============================================================
 * BARRIER command
 * ============================================================
 *
 * Semantics:
 *  - All prior commands must complete
 *  - No data payload
 */

struct henix_cmd_barrier {
    struct henix_cmd_hdr hdr;
    uint8_t payload[HENIX_CMD_PAYLOAD_SIZE];
};

struct henix_cmd_matmul {
    struct henix_cmd_hdr hdr;

    uint32_t M;
    uint32_t K;
    uint32_t N;

    uint32_t a_buf;  // user VA
    uint32_t b_buf;  // user VA
    uint32_t c_buf;  // user VA

    uint32_t flags;  // must be 0 for now

    uint8_t  reserved[HENIX_CMD_PAYLOAD_SIZE - 28];
};

#endif /* __HENIX_NPU_CONTRACT_H__ */
