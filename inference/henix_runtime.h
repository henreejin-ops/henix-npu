/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Henix NPU Runtime API
 *
 * This header defines the user-space C API for interacting with the Henix NPU.
 */

#ifndef __HENIX_RUNTIME_H__
#define __HENIX_RUNTIME_H__

#include <stdint.h>
#include "henix_def.h"

/* UAPI definitions - copied from henix_drv_test.c */
#define HENIX_IOC_MAGIC 'H'

struct henix_cmd {
    uint8_t data[HENIX_CMD_SLOT_SIZE];  /* opaque blob - 512 bytes */
    uint32_t seq;                        /* output: sequence number */
};

struct henix_user_alloc {
    uint32_t size;
    uint32_t handle;  /* output: buffer ID */
};

#define HENIX_IOCTL_SUBMIT \
    _IOWR(HENIX_IOC_MAGIC, 0x00, struct henix_cmd)
#define HENIX_IOCTL_ALLOC_BUF \
    _IOWR(HENIX_IOC_MAGIC, 0x01, struct henix_user_alloc)
#define HENIX_IOCTL_FREE_BUF \
    _IOWR(HENIX_IOC_MAGIC, 0x02, uint32_t)

/* Buffer FD mapping */
typedef struct {
    uint32_t handle;
    int fd;
    size_t size;
} buffer_fd_entry_t;

/* Maximum number of buffer FDs to track */
#define MAX_BUFFER_FDS 1024

/* Henix NPU context */
typedef struct {
    int fd;  /* device file descriptor */
    buffer_fd_entry_t buffer_fds[MAX_BUFFER_FDS];
    int num_buffer_fds;
} henix_ctx_t;

/* API functions */

/**
 * Open and initialize the Henix NPU device
 * @return Pointer to the Henix context, or NULL on failure
 */
henix_ctx_t* henix_open();

/**
 * Close the Henix NPU device and free resources
 * @param ctx Pointer to the Henix context
 */
void henix_close(henix_ctx_t* ctx);

/**
 * Perform matrix multiplication on the Henix NPU
 * @param ctx Pointer to the Henix context
 * @param A Pointer to matrix A [M x K]
 * @param B Pointer to matrix B [K x N]
 * @param C Pointer to output matrix C [M x N]
 * @param M Number of rows in A and C
 * @param K Number of columns in A and rows in B
 * @param N Number of columns in B and C
 * @return 0 on success, negative error code on failure
 */
int henix_matmul(
    henix_ctx_t* ctx,
    const float* A,
    const float* B,
    float* C,
    int M,
    int K,
    int N
);

#endif /* __HENIX_RUNTIME_H__ */
