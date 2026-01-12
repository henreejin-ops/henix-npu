/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Henix NPU Runtime API Implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include "henix_runtime.h"
#include "henix_def.h"

/**
 * Open and initialize the Henix NPU device
 * @return Pointer to the Henix context, or NULL on failure
 */
henix_ctx_t* henix_open() {
    fprintf(stderr, "TRACE: henix_open in\n");
    henix_ctx_t* ctx = (henix_ctx_t*)malloc(sizeof(henix_ctx_t));
    if (!ctx) {
        perror("malloc failed");
        fprintf(stderr, "TRACE: henix_open out (failure)\n");
        return NULL;
    }

    // Initialize buffer FD tracking
    ctx->num_buffer_fds = 0;
    memset(ctx->buffer_fds, 0, sizeof(ctx->buffer_fds));

    ctx->fd = open("/dev/henix-npu", O_RDWR);
    if (ctx->fd < 0) {
        perror("open /dev/henix-npu");
        free(ctx);
        fprintf(stderr, "TRACE: henix_open out (failure)\n");
        return NULL;
    }

    fprintf(stderr, "TRACE: henix_open out\n");
    return ctx;
}

/**
 * Close the Henix NPU device and free resources
 * @param ctx Pointer to the Henix context
 */
void henix_close(henix_ctx_t* ctx) {
    fprintf(stderr, "TRACE: henix_close in\n");
    if (ctx) {
        /* Clean up any remaining buffer FDs */
        for (int i = 0; i < ctx->num_buffer_fds; i++) {
            if (ctx->buffer_fds[i].fd >= 0) {
                if (close(ctx->buffer_fds[i].fd) < 0) {
                    perror("close buffer FD during cleanup");
                }
                ctx->buffer_fds[i].fd = -1;
            }
        }
        
        if (ctx->fd >= 0) {
            close(ctx->fd);
        }
        free(ctx);
    }
    fprintf(stderr, "TRACE: henix_close out\n");
}

/**
 * Build MATMUL command - using contract header structure
 */
static void build_matmul_cmd(struct henix_cmd *cmd,
                             const float* A,
                             const float* B,
                             float* C,
                             uint32_t M,
                             uint32_t K,
                             uint32_t N) {
    fprintf(stderr, "TRACE: build_matmul_cmd in\n");
    struct henix_cmd_matmul *matmul_cmd = (struct henix_cmd_matmul *)cmd->data;
    
    memset(cmd, 0, sizeof(*cmd));
    matmul_cmd->hdr.opcode = HENIX_CMD_MATMUL;
    matmul_cmd->M = M;
    matmul_cmd->K = K;
    matmul_cmd->N = N;
    matmul_cmd->a_buf = (uint32_t)(uint64_t)A;
    matmul_cmd->b_buf = (uint32_t)(uint64_t)B;
    matmul_cmd->c_buf = (uint32_t)(uint64_t)C;
    matmul_cmd->flags = 0;
    fprintf(stderr, "TRACE: build_matmul_cmd out\n");
}

/**
 * Copy data between CPU and NPU buffers
 * @param ctx Pointer to the Henix context
 * @param src_cpu Pointer to CPU source buffer (or NULL for NPU-to-NPU)
 * @param src_buf NPU source buffer handle (or 0 for CPU-to-CPU)
 * @param dst_cpu Pointer to CPU destination buffer (or NULL for NPU-to-NPU)
 * @param dst_buf NPU destination buffer handle (or 0 for CPU-to-CPU)
 * @param len Number of bytes to copy
 * @return 0 on success, negative error code on failure
 */
int henix_memcpy(
    henix_ctx_t* ctx,
    const void* src_cpu,
    uint32_t src_buf,
    void* dst_cpu,
    uint32_t dst_buf,
    uint32_t len
) {
    fprintf(stderr, "TRACE: henix_memcpy in\n");
    // For now, we'll just do a direct memcpy for CPU-to-CPU
    // In a full implementation, this would handle CPU-NPU transfers
    if (src_cpu && dst_cpu) {
        memcpy(dst_cpu, src_cpu, len);
        fprintf(stderr, "TRACE: henix_memcpy out\n");
        return 0;
    }
    
    fprintf(stderr, "NPU memory transfers not fully implemented yet\n");
    fprintf(stderr, "TRACE: henix_memcpy out\n");
    return -1;
}

/**
 * Submit command to the Henix NPU
 */
static int henix_submit_cmd(int fd, struct henix_cmd *cmd) {
    fprintf(stderr, "TRACE: henix_submit_cmd in\n");
    if (ioctl(fd, HENIX_IOCTL_SUBMIT, cmd) < 0) {
        perror("ioctl HENIX_IOCTL_SUBMIT");
        fprintf(stderr, "TRACE: henix_submit_cmd out (failure)\n");
        return -1;
    }

    fprintf(stderr, "TRACE: henix_submit_cmd out\n");
    return 0;
}

/**
 * Allocate a buffer on the Henix NPU and mmap it to user space
 * @param ctx Pointer to the Henix context
 * @param size Size of the buffer in bytes
 * @param buf_handle Output: Buffer handle
 * @return Pointer to the mmaped buffer, or NULL on failure
 */
void* henix_alloc_buf(henix_ctx_t* ctx, uint32_t size, uint32_t* buf_handle) {
    fprintf(stderr, "TRACE: henix_alloc_buf in\n");
    // Align size to 4K boundary (4096 bytes)
    uint32_t aligned_size = (size + 0xFFF) & ~0xFFF;
    struct henix_user_alloc req = {
        .size = aligned_size,
    };
    void* buf_ptr = NULL;
    int buf_fd = -1;
    
    if (!ctx || ctx->fd < 0 || !buf_handle) {
        fprintf(stderr, "Invalid Henix context or buffer handle pointer");
        fprintf(stderr, "TRACE: henix_alloc_buf out (failure)\n");
        return NULL;
    }

    /* The ioctl returns a buffer-specific FD */
    buf_fd = ioctl(ctx->fd, HENIX_IOCTL_ALLOC_BUF, &req);
    if (buf_fd < 0) {
        perror("ioctl HENIX_IOCTL_ALLOC_BUF");
        fprintf(stderr, "TRACE: henix_alloc_buf out (failure - ioctl)\n");
        fprintf(stderr, "TRACE: henix_alloc_buf out (failure - mmap)\n");
        fprintf(stderr, "TRACE: henix_matmul out (failure - alloc A)\n");
        fprintf(stderr, "TRACE: henix_matmul out (failure - alloc B)\n");
        fprintf(stderr, "TRACE: henix_matmul out (failure - alloc C)\n");
        goto cleanup;
    }

    /* Mmap the buffer into user space */
    buf_ptr = mmap(NULL,
                 aligned_size,
                 PROT_READ | PROT_WRITE,
                 MAP_SHARED,
                 buf_fd,
                 0);  /* offset is always 0 for buffer FDs */

    if (buf_ptr == MAP_FAILED) {
        perror("mmap");
        goto cleanup;
    }

    /* Store the buffer FD in the context for later cleanup */
    if (ctx->num_buffer_fds >= MAX_BUFFER_FDS) {
        fprintf(stderr, "ERROR: Too many buffer FDs, cannot store more\n");
        close(buf_fd);
        buf_ptr = MAP_FAILED;
        goto cleanup;
    }
    
    ctx->buffer_fds[ctx->num_buffer_fds].handle = req.handle;
    ctx->buffer_fds[ctx->num_buffer_fds].fd = buf_fd;
    ctx->buffer_fds[ctx->num_buffer_fds].size = aligned_size;
    ctx->num_buffer_fds++;
    
    /* Return the buffer handle and pointer */
    *buf_handle = req.handle;
    fprintf(stderr, "TRACE: henix_alloc_buf out\n");
    return buf_ptr;

cleanup:
    /* Ensure proper cleanup to prevent leaks */
    if (buf_fd >= 0) {
        close(buf_fd);
    }
    fprintf(stderr, "TRACE: henix_alloc_buf out (cleanup)\n");
    return NULL;
}

/**
 * Free a buffer allocated on the Henix NPU and unmap it
 * @param ctx Pointer to the Henix context
 * @param buf_handle Buffer handle to free
 * @param buf_ptr Pointer to the mmaped buffer
 * @param size Size of the buffer in bytes
 * @return 0 on success, negative error code on failure
 */
int henix_free_buf(henix_ctx_t* ctx, uint32_t buf_handle, void* buf_ptr, uint32_t size) {
    fprintf(stderr, "TRACE: henix_free_buf in\n");
    if (!ctx || ctx->fd < 0) {
        fprintf(stderr, "Invalid Henix context");
        fprintf(stderr, "TRACE: henix_free_buf out (failure)\n");
        return -1;
    }

    if (buf_ptr != NULL) {
        /* Unmap the buffer - use aligned size */
        uint32_t aligned_size = (size + 0xFFF) & ~0xFFF;
        if (munmap(buf_ptr, aligned_size) < 0) {
            perror("munmap");
            fprintf(stderr, "TRACE: henix_free_buf out (failure - munmap)\n");
            return -1;
        }
    }

    /* Find and close the buffer FD */
    int buf_fd = -1;
    for (int i = 0; i < ctx->num_buffer_fds; i++) {
        if (ctx->buffer_fds[i].handle == buf_handle) {
            buf_fd = ctx->buffer_fds[i].fd;
            
            /* Remove the entry by shifting remaining entries */
            for (int j = i; j < ctx->num_buffer_fds - 1; j++) {
                ctx->buffer_fds[j] = ctx->buffer_fds[j + 1];
            }
            ctx->num_buffer_fds--;
            
            /* Close the buffer FD */
            if (close(buf_fd) < 0) {
                perror("close buffer FD");
                fprintf(stderr, "TRACE: henix_free_buf out (warning - failed to close FD)\n");
                // Continue anyway - we still need to free the buffer on the NPU
            } else {
                fprintf(stderr, "TRACE: henix_free_buf - closed buffer FD\n");
            }
            break;
        }
    }

    // /* Free the buffer on the NPU */
    // if (ioctl(ctx->fd, HENIX_IOCTL_FREE_BUF, buf_handle) < 0) {
    //     perror("ioctl HENIX_IOCTL_FREE_BUF");
    //     fprintf(stderr, "TRACE: henix_free_buf out (failure - ioctl)\n");
    //     return -1;
    // }

    fprintf(stderr, "TRACE: henix_free_buf out\n");
    return 0;
}

/**
 * Perform matrix multiplication on the Henix NPU using Henix-allocated mmaped buffers
 * @param ctx Pointer to the Henix context
 * @param A Pointer to matrix A [M x K] (CPU memory)
 * @param B Pointer to matrix B [K x N] (CPU memory)
 * @param C Pointer to output matrix C [M x N] (CPU memory)
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
) {
    fprintf(stderr, "TRACE: henix_matmul in\n");
    struct henix_cmd cmd;
    uint32_t a_buf = 0, b_buf = 0, c_buf = 0;
    float* a_ptr = NULL, *b_ptr = NULL, *c_ptr = NULL;
    size_t a_size = M * K * sizeof(float);
    size_t b_size = K * N * sizeof(float);
    size_t c_size = M * N * sizeof(float);
    int ret = -1;
    
    if (!ctx || ctx->fd < 0) {
        fprintf(stderr, "Invalid Henix context");
        fprintf(stderr, "TRACE: henix_matmul out (failure)\n");
        return -1;
    }

    // Step 1: Allocate mmaped buffers on the Henix NPU
    a_ptr = (float*)henix_alloc_buf(ctx, a_size, &a_buf);
    if (a_ptr == NULL) {
        fprintf(stderr, "Failed to allocate buffer A on Henix NPU\n");
        goto cleanup;
    }
    
    b_ptr = (float*)henix_alloc_buf(ctx, b_size, &b_buf);
    if (b_ptr == NULL) {
        fprintf(stderr, "Failed to allocate buffer B on Henix NPU\n");
        goto cleanup;
    }
    
    c_ptr = (float*)henix_alloc_buf(ctx, c_size, &c_buf);
    if (c_ptr == NULL) {
        fprintf(stderr, "Failed to allocate buffer C on Henix NPU\n");
        goto cleanup;
    }

    // Step 2: Copy input matrices from CPU to mmaped NPU buffers
    memcpy(a_ptr, A, a_size);
    memcpy(b_ptr, B, b_size);

    // Step 3: Build and submit MATMUL command using NPU buffers
    struct henix_cmd_matmul *matmul_cmd = (struct henix_cmd_matmul *)cmd.data;
    memset(&cmd, 0, sizeof(cmd));
    matmul_cmd->hdr.opcode = HENIX_CMD_MATMUL;
    matmul_cmd->M = M;
    matmul_cmd->K = K;
    matmul_cmd->N = N;
    matmul_cmd->a_buf = a_buf;
    matmul_cmd->b_buf = b_buf;
    matmul_cmd->c_buf = c_buf;
    matmul_cmd->flags = 0;
    
    if (henix_submit_cmd(ctx->fd, &cmd) < 0) {
        fprintf(stderr, "Failed to submit MATMUL command to Henix NPU\n");
        fprintf(stderr, "TRACE: henix_matmul out (failure - submit)\n");
        goto cleanup;
    }

    // Step 4: Copy result back from mmaped NPU buffer to CPU buffer
    memcpy(C, c_ptr, c_size);

    ret = 0;
    fprintf(stderr, "TRACE: henix_matmul out\n");

cleanup:
    // Free the allocated NPU buffers and unmap them
    if (a_ptr != NULL && a_buf != 0) {
        henix_free_buf(ctx, a_buf, a_ptr, a_size);
    }
    if (b_ptr != NULL && b_buf != 0) {
        henix_free_buf(ctx, b_buf, b_ptr, b_size);
    }
    if (c_ptr != NULL && c_buf != 0) {
        henix_free_buf(ctx, c_buf, c_ptr, c_size);
    }
    
    fprintf(stderr, "TRACE: henix_matmul out (cleanup)\n");
    return ret;
}
