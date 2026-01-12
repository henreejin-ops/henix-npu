/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_HENIX_NPU_H_
#define _UAPI_HENIX_NPU_H_

#include <linux/types.h>

#define HENIX_IOC_MAGIC 'H'

/* Opcodes (for userspace reference - command composition is userspace's job) */
#define HENIX_CMD_MEMCPY 0x01

/* Command structure - driver treats as opaque, userspace defines layout */
/* Command slot size: 512 bytes (defined in henix_def.h) */
struct henix_cmd {
    __u8 data[512];  /* opaque command blob - userspace defines content */
    __u32 seq;       /* output: sequence number assigned by driver */
};

/* Buffer allocation request - driver manages resources */
struct henix_user_alloc {
    __u32 size;
    __u32 handle;  /* output: buffer ID */
};

/* IOCTL definitions */
#define HENIX_IOCTL_SUBMIT \
    _IOWR(HENIX_IOC_MAGIC, 0x00, struct henix_cmd)
#define HENIX_IOCTL_ALLOC_BUF \
    _IOWR(HENIX_IOC_MAGIC, 0x01, struct henix_user_alloc)
#define HENIX_IOCTL_FREE_BUF \
    _IOW(HENIX_IOC_MAGIC, 0x02, __u32)

#endif

