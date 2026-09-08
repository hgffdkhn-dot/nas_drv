# NAS 驱动 Makefile
#
# 关键：必须在 4.14.186 的完整内核源码树下编译，否则 vermagic 不匹配，
#       insmod 会报 "version magic ... should be ..." 并拒绝加载。
#
# 用法：
#   make KDIR=/path/to/kernel-4.14.186 \
#        ARCH=arm64 \
#        CROSS_COMPILE=aarch64-linux-android- 
#
# Android 内核常用交叉工具链：
#   aarch64-linux-android-     (NDK / AOSP prebuilts)
#   aarch64-linux-gnu-         (发行版通用)

obj-m += nas_drv.o

KDIR ?= /path/to/kernel-4.14.186
ARCH ?= arm64
CROSS_COMPILE ?= aarch64-linux-android-

# 若目标内核开启了模块签名/校验，需要在源码树配置中关闭或自行签名：
#   CONFIG_MODULE_SIG=n
#   CONFIG_MODVERSIONS 需与源码树一致（本 Makefile 依赖 KDIR 的 Module.symvers）

EXTRA_CFLAGS += -Wall -Wextra -Wno-unused-parameter

all:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=$(ARCH) \
		CROSS_COMPILE=$(CROSS_COMPILE) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=$(ARCH) \
		CROSS_COMPILE=$(CROSS_COMPILE) clean

# 仅做语法/静态检查，不需要完整源码树
check:
	$(CROSS_COMPILE)gcc -fsyntax-only -D__KERNEL__ \
		-nostdinc -isystem $(KDIR)/include \
		-Wall nas_drv.c

.PHONY: all clean check
