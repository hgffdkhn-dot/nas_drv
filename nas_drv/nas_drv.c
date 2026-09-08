/*
 * NAS 驱动 —— 进程内存访问 / 模块基址查询
 *
 * 目标内核：Linux 4.14.186 (aarch64, Android common kernel 分支)
 *
 * 功能：
 *   - 通过 /dev/<name> 字符设备提供 ioctl 接口
 *   - NAS_IOC_READ_MEM  : 读取指定进程的虚拟内存
 *   - NAS_IOC_WRITE_MEM : 写入指定进程的虚拟内存
 *   - NAS_IOC_MOD_BASE  : 在指定进程的 VMA 中按文件名匹配，返回其起始地址
 *   - NAS_IOC_VERSION   : 返回接口版本号
 *
 * 设计说明（与逆向样本 entryi.ko 的对照）：
 *
 *   1) 内存访问走 access_process_vm()，而不是手工遍历四级页表。
 *      原样本自己实现 translate_linear_address()：只把起始虚拟地址翻译
 *      一次，就拿这个物理地址去拷贝整个 size。一旦 addr+size 跨页，
 *      物理地址并不连续，读到的是物理相邻但逻辑无关的内存 —— 这是
 *      实打实的正确性 bug。access_process_vm() 由内核逐页处理，
 *      天然正确，且是导出符号，不依赖 memstart_addr 等非导出符号。
 *
 *   2) 不使用全局 bss 缓冲。原样本把所有请求拷进 .bss 固定偏移且无锁，
 *      并发 ioctl 会互相覆盖。本驱动每次调用独立 kmalloc。
 *
 *   3) 不做任何隐藏动作：不从模块链表摘链、不删除 /proc 条目、
 *      设备节点常驻可见。模块保持可 rmmod、可在 /proc/modules 中列出。
 *
 *   4) 基础访问控制：设备节点默认 0600（仅 root 可访问），
 *      可用模块参数 dev_mode 调整。
 *
 * 编译：见 Makefile，需要 4.14.186 的完整内核源码树（vermagic 强匹配）。
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/mm.h>
#include <linux/mm.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/limits.h>
#include <linux/version.h>

#include "nas_drv.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("nas");
MODULE_DESCRIPTION("NAS driver - process memory access / module base lookup");
MODULE_VERSION("1");

/* 注意：MODULE_INFO(vermagic, ...) 由内核构建系统自动注入，
 *       不要手写，否则与 4.14.186 源码树编译出的版本串不一致。 */

/* ---------------- 模块参数 ---------------- */

static char *dev_name = "nas";
module_param(dev_name, charp, 0444);
MODULE_PARM_DESC(dev_name, "device node name under /dev (default: nas)");

static uint dev_mode = 0600;
module_param(dev_mode, uint, 0644);
MODULE_PARM_DESC(dev_mode, "device node permission bits (default: 0600)");

/* ---------------- 全局状态 ---------------- */

static dev_t   nas_devt;
static struct cdev   nas_cdev;
static struct class *nas_class;
static struct device *nas_device;

/* ---------------- 目标进程获取 ---------------- */

/*
 * 由 pid 取得 task_struct，并持有其引用。
 * 调用者成功后必须配对 put_task_struct()。
 */
static struct task_struct *nas_get_task(int pid_nr)
{
	struct pid *pid;
	struct task_struct *task;

	pid = find_get_pid(pid_nr);
	if (!pid)
		return ERR_PTR(-ESRCH);

	task = get_pid_task(pid, PIDTYPE_PID);
	put_pid(pid);          /* get_pid_task 已自带引用，这里释放 find_get_pid 的 */
	if (!task)
		return ERR_PTR(-ESRCH);

	return task;
}

/* ---------------- 0x01 读进程内存 ---------------- */

static int nas_read_mem(struct nas_rw_req *req)
{
	struct task_struct *task;
	struct mm_struct *mm;
	void *kbuf;
	int copied;
	int ret = 0;

	if (req->size == 0 || req->size > NAS_MAX_XFER)
		return -EINVAL;
	if (req->reserved != 0)
		return -EINVAL;

	kbuf = kmalloc(req->size, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	task = nas_get_task(req->pid);
	if (IS_ERR(task)) {
		ret = PTR_ERR(task);
		goto out_free;
	}

	mm = get_task_mm(task);
	if (!mm) {
		ret = -ESRCH;      /* 内核线程没有用户态地址空间 */
		goto out_put_task;
	}

	/*
	 * gup_flags = 0 表示读取。
	 * 返回值为实际拷贝字节数，短拷贝说明中途遇到未映射页。
	 */
	copied = access_process_vm(task, req->remote_addr, kbuf,
				   (int)req->size, 0);
	mmput(mm);

	if (copied <= 0) {
		ret = -EIO;
		goto out_put_task;
	}

	if (copy_to_user((void __user *)(uintptr_t)req->user_buf,
			 kbuf, (size_t)copied)) {
		ret = -EFAULT;
		goto out_put_task;
	}

	req->size = (u64)copied;   /* 回填实际长度，调用方可识别短读 */

out_put_task:
	put_task_struct(task);
out_free:
	kfree(kbuf);
	return ret;
}

/* ---------------- 0x02 写进程内存 ---------------- */

static int nas_write_mem(struct nas_rw_req *req)
{
	struct task_struct *task;
	struct mm_struct *mm;
	void *kbuf;
	int copied;
	int ret = 0;

	if (req->size == 0 || req->size > NAS_MAX_XFER)
		return -EINVAL;
	if (req->reserved != 0)
		return -EINVAL;

	kbuf = kmalloc(req->size, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	/* 先把用户态数据拉进内核，再写入目标进程 */
	if (copy_from_user(kbuf,
			   (void __user *)(uintptr_t)req->user_buf,
			   req->size)) {
		ret = -EFAULT;
		goto out_free;
	}

	task = nas_get_task(req->pid);
	if (IS_ERR(task)) {
		ret = PTR_ERR(task);
		goto out_free;
	}

	mm = get_task_mm(task);
	if (!mm) {
		ret = -ESRCH;
		goto out_put_task;
	}

	/*
	 * FOLL_WRITE 表示写入。对只读 VMA 会失败（返回 0 或短拷贝），
	 * 这正是我们期望的权限行为，不做 FORCE 绕过。
	 */
	copied = access_process_vm(task, req->remote_addr, kbuf,
				   (int)req->size, FOLL_WRITE);
	mmput(mm);

	if (copied <= 0) {
		ret = -EPERM;
		goto out_put_task;
	}

	req->size = (u64)copied;

out_put_task:
	put_task_struct(task);
out_free:
	kfree(kbuf);
	return ret;
}

/* ---------------- 0x03 查询模块基址 ---------------- */

/*
 * 在目标进程的 VMA 链表中，按映射文件名匹配，返回首个命中的 vm_start。
 * flags == 0 : 子串匹配（d_path 全路径中查找）
 * flags == 1 : 精确匹配 basename（dentry 名字）
 */
static unsigned long nas_lookup_base(struct mm_struct *mm,
				     const char *name, u32 flags)
{
	struct vm_area_struct *vma;
	char *pathbuf;
	char *p;
	unsigned long base = 0;

	pathbuf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!pathbuf)
		return 0;

	down_read(&mm->mmap_sem);

	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if (!vma->vm_file)
			continue;

		if (flags == 1) {
			/* 精确匹配 basename，如 libfoo.so */
			struct dentry *d = vma->vm_file->f_path.dentry;
			if (strcmp(d->d_name.name, name) == 0) {
				base = vma->vm_start;
				break;
			}
			continue;
		}

		/* 子串匹配：对完整路径做匹配，可传 /data/app/.../libfoo.so */
		p = d_path(&vma->vm_file->f_path, pathbuf, PATH_MAX);
		if (IS_ERR(p))
			continue;
		if (strstr(p, name)) {
			base = vma->vm_start;
			break;
		}
	}

	up_read(&mm->mmap_sem);
	kfree(pathbuf);
	return base;
}

static int nas_get_mod_base(struct nas_mod_req *req)
{
	struct task_struct *task;
	struct mm_struct *mm;
	char *name;
	unsigned long base;
	int ret = 0;

	name = kzalloc(NAS_NAME_MAX, GFP_KERNEL);
	if (!name)
		return -ENOMEM;

	if (copy_from_user(name,
			   (void __user *)(uintptr_t)req->name_ptr,
			   NAS_NAME_MAX - 1)) {
		ret = -EFAULT;
		goto out_free;
	}
	name[NAS_NAME_MAX - 1] = '\0';

	task = nas_get_task(req->pid);
	if (IS_ERR(task)) {
		ret = PTR_ERR(task);
		goto out_free;
	}

	mm = get_task_mm(task);
	if (!mm) {
		ret = -ESRCH;
		goto out_put_task;
	}

	base = nas_lookup_base(mm, name, req->flags);
	mmput(mm);

	/* req 是内核副本，直接赋值；由 nas_ioctl 统一 copy_to_user 写回 */
	req->out_base = (__u64)base;

out_put_task:
	put_task_struct(task);
out_free:
	kfree(name);
	return ret;
}

/* ---------------- file_operations ---------------- */

static int nas_open(struct inode *inode, struct file *filp)
{
	/* 无 per-fd 私有数据，简单返回 */
	return 0;
}

static int nas_release(struct inode *inode, struct file *filp)
{
	return 0;
}

static long nas_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	struct nas_rw_req  rw;
	struct nas_mod_req mr;
	u32 ver = NAS_DRV_VERSION;
	int ret;

	/* magic 校验；_IOC_SIZE 与结构体大小不匹配时内核已先行拦截，
	 * 这里再确认一次，防止用户态头文件版本不一致。 */
	if (_IOC_TYPE(cmd) != NAS_IOC_MAGIC)
		return -ENOTTY;

	switch (cmd) {
	case NAS_IOC_READ_MEM:
		if (copy_from_user(&rw, argp, sizeof(rw)))
			return -EFAULT;
		ret = nas_read_mem(&rw);
		if (ret)
			return ret;          /* 透传 ESRCH/EINVAL/ENOMEM/EIO */
		if (copy_to_user(argp, &rw, sizeof(rw)))
			return -EFAULT;
		return 0;

	case NAS_IOC_WRITE_MEM:
		if (copy_from_user(&rw, argp, sizeof(rw)))
			return -EFAULT;
		ret = nas_write_mem(&rw);
		if (ret)
			return ret;          /* 透传 ESRCH/EINVAL/EPERM/ENOMEM */
		if (copy_to_user(argp, &rw, sizeof(rw)))
			return -EFAULT;
		return 0;

	case NAS_IOC_MOD_BASE:
		if (copy_from_user(&mr, argp, sizeof(mr)))
			return -EFAULT;
		ret = nas_get_mod_base(&mr);
		if (ret)
			return ret;
		if (copy_to_user(argp, &mr, sizeof(mr)))
			return -EFAULT;
		return 0;

	case NAS_IOC_VERSION:
		if (copy_to_user(argp, &ver, sizeof(ver)))
			return -EFAULT;
		return 0;

	default:
		return -ENOTTY;
	}
}

static const struct file_operations nas_fops = {
	.owner          = THIS_MODULE,
	.open           = nas_open,
	.release        = nas_release,
	.unlocked_ioctl = nas_ioctl,
	/*
	 * 不提供 compat_ioctl：32 位用户态在 arm64 上的 ioctl 命令号编码
	 * 与 64 位不同，简单复用会绕过 _IOC_SIZE 校验。
	 * 若确有 32 位调用方需求，应单独实现并做 compat_ptr 转换。
	 */
};

/*
 * devtmpfs 节点权限由 udev 策略决定，模块无法直接 chmod。
 * 标准做法是通过 uevent 导出 DEVMODE，由 udev 应用。
 */
static int nas_dev_uevent(struct device *dev, struct kobj_uevent_env *env)
{
	return add_uevent_var(env, "DEVMODE=%04o", dev_mode);
}

/* ---------------- 模块初始化 / 退出 ---------------- */

static int __init nas_init(void)
{
	int ret;

	/* 1. 动态申请设备号 */
	ret = alloc_chrdev_region(&nas_devt, 0, 1, dev_name);
	if (ret < 0) {
		pr_err("nas: alloc_chrdev_region failed: %d\n", ret);
		return ret;
	}

	/* 2. 注册字符设备 */
	cdev_init(&nas_cdev, &nas_fops);
	nas_cdev.owner = THIS_MODULE;

	ret = cdev_add(&nas_cdev, nas_devt, 1);
	if (ret < 0) {
		pr_err("nas: cdev_add failed: %d\n", ret);
		goto err_unregister_region;
	}

	/* 3. 创建 class 与设备节点（常驻可见，不做任何隐藏） */
	nas_class = class_create(THIS_MODULE, dev_name);
	if (IS_ERR(nas_class)) {
		ret = PTR_ERR(nas_class);
		pr_err("nas: class_create failed: %d\n", ret);
		goto err_cdev_del;
	}
	nas_class->dev_uevent = nas_dev_uevent;

	nas_device = device_create(nas_class, NULL, nas_devt, NULL,
				   dev_name);
	if (IS_ERR(nas_device)) {
		ret = PTR_ERR(nas_device);
		pr_err("nas: device_create failed: %d\n", ret);
		goto err_class_destroy;
	}

	/* 4. 权限已通过 class->dev_uevent 导出 DEVMODE，由 udev 应用。
	 *    无 udev 时（多数 Android 环境）默认节点权限为 0600。 */

	pr_info("nas: loaded, /dev/%s (major=%d minor=%d, mode=%04o)\n",
		dev_name, MAJOR(nas_devt), MINOR(nas_devt), dev_mode);
	pr_info("nas: kernel %s, iface v%d\n", UTS_RELEASE, NAS_DRV_VERSION);

	return 0;

err_class_destroy:
	class_destroy(nas_class);
err_cdev_del:
	cdev_del(&nas_cdev);
err_unregister_region:
	unregister_chrdev_region(nas_devt, 1);
	return ret;
}

static void __exit nas_exit(void)
{
	device_destroy(nas_class, nas_devt);
	class_destroy(nas_class);
	cdev_del(&nas_cdev);
	unregister_chrdev_region(nas_devt, 1);
	pr_info("nas: unloaded\n");
}

module_init(nas_init);
module_exit(nas_exit);
