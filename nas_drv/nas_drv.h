/*
 * NAS 驱动 —— 用户态接口定义
 *
 * 目标内核：Linux 4.14.186 (aarch64)
 *
 * 本头文件同时供内核态(nas_drv.c)与用户态测试程序使用。
 *
 * 与原逆向样本(entryi.ko)的差异：
 *   1. 命令号使用标准 _IOWR/_IOR 宏编码（含 magic + size 校验），
 *      而不是驱动里直接比较的裸值 0x801/0x802 —— 标准宏能让内核
 *      帮你校验结构体大小，传错 size 会返回 ENOTTY 而不是越界访问。
 *   2. 结构体显式补齐 padding，不依赖编译器隐式对齐。
 *   3. 不提供“节点创建/销毁”这类用于隐藏的控制命令。
 */
#ifndef NAS_DRV_H
#define NAS_DRV_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define NAS_IOC_MAGIC  'N'
#define NAS_DRV_VERSION 1

/* 单次传输上限，防止一次 ioctl 分配过大内核内存 */
#define NAS_MAX_XFER   (1UL << 20)   /* 1 MiB */

/* 单次节点名/模块名最大长度 */
#define NAS_NAME_MAX   256

/* ---------- 0x01 读 / 0x02 写：进程内存读写 ---------- */
struct nas_rw_req {
	__s32  pid;          /* +0x00 目标进程 PID                    */
	__u32  reserved;     /* +0x04 显式 padding，必须置 0          */
	__u64  remote_addr;  /* +0x08 目标进程内的虚拟地址            */
	__u64  user_buf;     /* +0x10 本进程用户态缓冲区地址          */
	__u64  size;         /* +0x18 字节数，不超过 NAS_MAX_XFER     */
};

/* ---------- 0x03 查询目标进程内某模块的基址 ---------- */
struct nas_mod_req {
	__s32  pid;          /* +0x00 目标进程 PID                       */
	__u32  flags;        /* +0x04 0=子串匹配 1=精确 basename 匹配    */
	__u64  name_ptr;     /* +0x08 用户态 char[NAS_NAME_MAX] 缓冲区   */
	__u64  out_base;     /* +0x10 输出：命中的 VMA 起始地址，0=未找到 */
};

#define NAS_IOC_READ_MEM   _IOWR(NAS_IOC_MAGIC, 0x01, struct nas_rw_req)
#define NAS_IOC_WRITE_MEM  _IOWR(NAS_IOC_MAGIC, 0x02, struct nas_rw_req)
#define NAS_IOC_MOD_BASE   _IOWR(NAS_IOC_MAGIC, 0x03, struct nas_mod_req)
#define NAS_IOC_VERSION    _IOR (NAS_IOC_MAGIC, 0x04, __u32)

/*
 * 返回值约定（ioctl 返回值，0 表示成功）：
 *   0        成功
 *   -EINVAL  参数非法（size 为 0 / 超上限 / reserved 非 0）
 *   -ESRCH   目标 PID 不存在或为内核线程（无 mm）
 *   -EFAULT  用户态缓冲区不可访问
 *   -ENOMEM  内核内存分配失败
 *   -EPERM   目标地址所在 VMA 不允许本次操作
 *
 * 注意 NAS_IOC_MOD_BASE 成功时返回 0，基址通过 out_base 输出；
 *      未找到时同样返回 0，out_base == 0。
 */

#endif /* NAS_DRV_H */
