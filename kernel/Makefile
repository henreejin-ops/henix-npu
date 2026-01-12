# SPDX-License-Identifier: GPL-2.0

obj-m += henix_npu.o

# AArch64 cross-compilation settings
LINUX_DIR ?= /home/henree/work/open_source/linux
ARCH = arm64
CROSS_COMPILE = aarch64-linux-gnu-

all:
	$(MAKE) -C $(LINUX_DIR) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(LINUX_DIR) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) M=$(CURDIR) clean
