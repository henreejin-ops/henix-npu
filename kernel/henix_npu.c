// SPDX-License-Identifier: GPL-2.0
/*
 * Henix NPU Command Processor Driver
 *
 * Driver that binds to Henix NPU device, maps MMIO,
 * submits commands, handles IRQs, and provides userspace API.
 */

#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/delay.h>
#include <linux/of.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/poll.h>
#include <linux/fs.h>
#include <linux/henix_npu.h>
#include <linux/dma-mapping.h>
#include <linux/anon_inodes.h>
#include <linux/file.h>     /* for put_unused_fd */
#include "henix_def.h"



#define HENIX_CMD_SIZE   512
#define HENIX_CMD_DEPTH (0x1000 / HENIX_CMD_SIZE)  /* 8 commands total */



struct henix_buffer {
    struct henix_dev *hdev;
    void *cpu_addr;
    dma_addr_t dma_addr;
    u32 size;
    u32 flags;
    u32 buf_id;
    atomic_t refcount;
};

/* Buffer table entry format expected by hardware */
struct henix_buffer_desc {
    u64 addr;       /* DMA address (GPA / IOVA) - what hardware uses */
    u32 size;       /* buffer size */
    u32 flags;      /* reserved */
};

#define HENIX_BUF_TABLE_SIZE 256

struct henix_dev {
    struct device *dev;
    void __iomem  *mmio;

    u32 next_seq;
    u32 completed_seq;

    spinlock_t lock;
    wait_queue_head_t wq;

    int irq;

    /* char device */
    struct miscdevice miscdev;

    /* buffer table management */
    struct henix_buffer_desc *buf_table;
    struct henix_buffer **buf_ptrs;  /* array of buffer pointers for lookup */
    dma_addr_t buf_table_dma;
    u32 buf_table_size;
    bool *buf_table_in_use;
};

/* Forward declarations */
static const struct file_operations henix_fops;
static const struct file_operations henix_buf_fops;
static void henix_reload_buf_table(struct henix_dev *hdev);

#define REG_CMD_SRAM        0x0000
#define REG_CMD_HEAD        0x1000
#define REG_CMD_TAIL        0x1004
#define REG_CMD_DOORBELL    0x1008
#define REG_IRQ_STATUS      0x1010
#define REG_IRQ_ENABLE      0x1014
#define REG_COMPLETED_SEQ   0x1018
#define REG_IRQ_ACK         0x101C
#define REG_BT_BASE_LO      0x1020
#define REG_BT_BASE_HI      0x1024
#define REG_BT_SIZE         0x1028
#define REG_BT_RELOAD       0x102C

static struct henix_buffer *henix_alloc_buffer(struct henix_dev *hdev, u32 size)
{
    int i;
    unsigned long flags;
    void *virt;
    dma_addr_t dma_addr;
    struct henix_buffer *buf;

    /* Allocate buffer struct */
    buf = kzalloc(sizeof(*buf), GFP_KERNEL);
    if (!buf) {
        return ERR_PTR(-ENOMEM);
    }

    /* Allocate buffer */
    virt = dma_alloc_coherent(hdev->dev, size, &dma_addr, GFP_KERNEL);
    if (!virt) {
        dev_err(hdev->dev, "Failed to allocate DMA buffer of size %u\n", size);
        kfree(buf);
        return ERR_PTR(-ENOMEM);
    }

    spin_lock_irqsave(&hdev->lock, flags);

    /* Find free buffer table entry */
    for (i = 0; i < HENIX_BUF_TABLE_SIZE; i++) {
        if (!hdev->buf_table_in_use[i]) {
            hdev->buf_table_in_use[i] = true;
            break;
        }
    }

    if (i == HENIX_BUF_TABLE_SIZE) {
        spin_unlock_irqrestore(&hdev->lock, flags);
        dma_free_coherent(hdev->dev, size, virt, dma_addr);
        kfree(buf);
        dev_err(hdev->dev, "Buffer table full\n");
        return ERR_PTR(-ENOSPC);
    }

    /* Initialize buffer struct */
    buf->hdev = hdev;
    buf->cpu_addr = virt;
    buf->dma_addr = dma_addr;
    buf->size = size;
    buf->flags = 0;
    buf->buf_id = i;
    atomic_set(&buf->refcount, 1);

    /* Update buffer table with hardware-expected format */
    hdev->buf_table[i].addr = dma_addr;  /* Only DMA address is visible to hardware */
    hdev->buf_table[i].size = size;
    hdev->buf_table[i].flags = 0;
    
    /* Update buffer pointers array */
    hdev->buf_ptrs[i] = buf;
    
    spin_unlock_irqrestore(&hdev->lock, flags);

    /* Reload buffer table */
    henix_reload_buf_table(hdev);

    dev_info(hdev->dev, "Allocated buffer %u: virt=%p, dma=%pad, size=%u\n",
            i, virt, &dma_addr, size);

    return buf;
}

static void henix_buffer_release(struct henix_buffer *buf)
{
    struct henix_dev *hdev = buf->hdev;
    unsigned long flags;

    spin_lock_irqsave(&hdev->lock, flags);
    
    /* Mark as free */
    hdev->buf_table_in_use[buf->buf_id] = false;
    hdev->buf_table[buf->buf_id].addr = 0;  /* Clear DMA address */
    hdev->buf_table[buf->buf_id].size = 0;
    hdev->buf_table[buf->buf_id].flags = 0;
    
    /* Clear buffer pointer */
    hdev->buf_ptrs[buf->buf_id] = NULL;
    
    spin_unlock_irqrestore(&hdev->lock, flags);

    /* Reload buffer table */
    henix_reload_buf_table(hdev);

    /* Free the DMA buffer */
    dma_free_coherent(hdev->dev, buf->size, buf->cpu_addr, buf->dma_addr);
    
    /* Free the buffer struct */
    kfree(buf);

    dev_dbg(hdev->dev, "Freed buffer %u\n", buf->buf_id);
}

static void henix_buffer_put(struct henix_buffer *buf)
{
    if (atomic_dec_and_test(&buf->refcount)) {
        henix_buffer_release(buf);
    }
}

static int henix_free_buffer(struct henix_dev *hdev, u32 buf_id)
{
    struct henix_buffer *buf;

    if (buf_id >= HENIX_BUF_TABLE_SIZE) {
        dev_err(hdev->dev, "Invalid buffer ID %u\n", buf_id);
        return -EINVAL;
    }

    buf = hdev->buf_ptrs[buf_id];
    if (!buf) {
        dev_err(hdev->dev, "Buffer %u not in use\n", buf_id);
        return -EINVAL;
    }

    henix_buffer_put(buf);
    return 0;
}

static void henix_reload_buf_table(struct henix_dev *hdev)
{
    /* Update buffer table memory */
    dma_wmb(); /* Ensure buffer table writes are visible to device */

    /* Program metadata */
    writel(lower_32_bits(hdev->buf_table_dma), hdev->mmio + REG_BT_BASE_LO);
    writel(upper_32_bits(hdev->buf_table_dma), hdev->mmio + REG_BT_BASE_HI);
    writel(HENIX_BUF_TABLE_SIZE, hdev->mmio + REG_BT_SIZE);

    /* Explicit reload trigger */
    writel(1, hdev->mmio + REG_BT_RELOAD);
}

static int henix_buf_mmap(struct file *filp, struct vm_area_struct *vma)
{
    struct henix_buffer *buf = filp->private_data;
    struct henix_dev *hdev = buf->hdev;

    dev_info(hdev->dev, "buf_mmap: buf_id=%u, size=%lu\n",
             buf->buf_id, vma->vm_end - vma->vm_start);

    if (vma->vm_pgoff != 0) {
        dev_err(hdev->dev, "Invalid offset for buffer mmap\n");
        return -EINVAL;
    }

    if (vma->vm_end - vma->vm_start > buf->size) {
        dev_err(hdev->dev, "mmap size exceeds buffer size\n");
        return -EINVAL;
    }

    /* Map the buffer to user space */
    return dma_mmap_coherent(hdev->dev, vma, buf->cpu_addr, 
                            buf->dma_addr, buf->size);
}

static int henix_buf_release(struct inode *inode, struct file *filp)
{
    struct henix_buffer *buf = filp->private_data;
    henix_buffer_put(buf);
    return 0;
}

static irqreturn_t henix_irq_handler(int irq, void *data)
{
    struct henix_dev *hdev = data;
    u32 seq;

    seq = readl(hdev->mmio + REG_COMPLETED_SEQ);

    spin_lock(&hdev->lock);
    hdev->completed_seq = seq;
    spin_unlock(&hdev->lock);

    dev_info(hdev->dev, "IRQ handler: completed_seq=%u\n", seq);

    wake_up_all(&hdev->wq);

    /* Ack interrupt */
    writel(1, hdev->mmio + REG_IRQ_ACK);

    return IRQ_HANDLED;
}





static int henix_probe(struct platform_device *pdev)
{
    struct henix_dev *hdev;
    struct resource *res;
    int ret;

    dev_info(&pdev->dev, "Probing Henix NPU device\n");

    hdev = devm_kzalloc(&pdev->dev, sizeof(*hdev), GFP_KERNEL);
    if (!hdev)
        return -ENOMEM;

    res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
    hdev->mmio = devm_ioremap_resource(&pdev->dev, res);
    if (IS_ERR(hdev->mmio))
        return PTR_ERR(hdev->mmio);

    hdev->irq = platform_get_irq(pdev, 0);
    if (hdev->irq < 0)
        return hdev->irq;

    spin_lock_init(&hdev->lock);
    init_waitqueue_head(&hdev->wq);

    hdev->next_seq = 0;
    hdev->completed_seq = 0;

    hdev->dev = &pdev->dev;

    /* Allocate buffer table */
    hdev->buf_table = dma_alloc_coherent(hdev->dev, sizeof(*hdev->buf_table) * HENIX_BUF_TABLE_SIZE, 
                                         &hdev->buf_table_dma, GFP_KERNEL);
    if (!hdev->buf_table) {
        dev_err(&pdev->dev, "Failed to allocate buffer table\n");
        return -ENOMEM;
    }

    /* Allocate buffer pointers array for lookup */
    hdev->buf_ptrs = devm_kcalloc(&pdev->dev, HENIX_BUF_TABLE_SIZE, sizeof(struct henix_buffer *), GFP_KERNEL);
    if (!hdev->buf_ptrs) {
        dev_err(&pdev->dev, "Failed to allocate buffer pointers array\n");
        dma_free_coherent(hdev->dev, sizeof(*hdev->buf_table) * HENIX_BUF_TABLE_SIZE, 
                         hdev->buf_table, hdev->buf_table_dma);
        return -ENOMEM;
    }

    /* Allocate buffer table in-use tracking */
    hdev->buf_table_in_use = devm_kcalloc(&pdev->dev, HENIX_BUF_TABLE_SIZE, sizeof(bool), GFP_KERNEL);
    if (!hdev->buf_table_in_use) {
        dev_err(&pdev->dev, "Failed to allocate buffer table in-use array\n");
        dma_free_coherent(hdev->dev, sizeof(*hdev->buf_table) * HENIX_BUF_TABLE_SIZE, 
                         hdev->buf_table, hdev->buf_table_dma);
        return -ENOMEM;
    }

    hdev->buf_table_size = HENIX_BUF_TABLE_SIZE;

    /* Initialize buffer table */
    memset(hdev->buf_table, 0, sizeof(*hdev->buf_table) * HENIX_BUF_TABLE_SIZE);
    memset(hdev->buf_ptrs, 0, HENIX_BUF_TABLE_SIZE * sizeof(struct henix_buffer *));
    memset(hdev->buf_table_in_use, 0, HENIX_BUF_TABLE_SIZE * sizeof(bool));

    /* Reload buffer table initially */
    henix_reload_buf_table(hdev);

    ret = devm_request_irq(&pdev->dev, hdev->irq,
                           henix_irq_handler,
                           0, "henix-npu", hdev);
    if (ret)
        return ret;

    /* Initialize misc device */
    hdev->miscdev.minor = MISC_DYNAMIC_MINOR;
    hdev->miscdev.name  = "henix-npu";
    hdev->miscdev.fops  = &henix_fops;
    hdev->miscdev.parent = &pdev->dev;
    hdev->miscdev.mode  = 0666;

    ret = misc_register(&hdev->miscdev);
    if (ret) {
        dev_err(&pdev->dev, "Failed to register misc device\n");
        return ret;
    }

    /* Enable interrupts */
    writel(1, hdev->mmio + REG_IRQ_ENABLE);

    platform_set_drvdata(pdev, hdev);

    dev_info(&pdev->dev, "Henix NPU driver loaded\n");
    return 0;
}

static int henix_open(struct inode *inode, struct file *filp)
{
    struct miscdevice *miscdev = filp->private_data;
    struct henix_dev *hdev = container_of(miscdev, struct henix_dev, miscdev);
    filp->private_data = hdev;
    return 0;
}

static long henix_ioctl(struct file *filp,
                        unsigned int cmd,
                        unsigned long arg)
{
    struct henix_dev *hdev = filp->private_data;
    int ret;

    switch (cmd) {
    case HENIX_IOCTL_ALLOC_BUF: {
        struct henix_user_alloc args;
        struct henix_buffer *buf;
        int fd;

        if (copy_from_user(&args, (void __user *)arg, sizeof(args))) {
            return -EFAULT;
        }

        buf = henix_alloc_buffer(hdev, args.size);
        if (IS_ERR(buf)) {
            return PTR_ERR(buf);
        }

        /* Get a new file descriptor for this buffer */
        fd = anon_inode_getfd("henix-buf", &henix_buf_fops, buf, O_RDWR | O_CLOEXEC);
        if (fd < 0) {
            henix_buffer_put(buf);
            return fd;
        }

        /* Return the buffer ID to userspace */
        args.handle = buf->buf_id;
        if (copy_to_user((void __user *)arg, &args, sizeof(args))) {
            put_unused_fd(fd);
            henix_buffer_put(buf);
            return -EFAULT;
        }

        /* Return the buffer FD to userspace */
        return fd;
    }

    case HENIX_IOCTL_FREE_BUF: {
        u32 buf_id;
        if (copy_from_user(&buf_id, (void __user *)arg, sizeof(buf_id))) {
            return -EFAULT;
        }

        return henix_free_buffer(hdev, buf_id);
    }

    case HENIX_IOCTL_SUBMIT: {
        struct henix_cmd args;
        u32 seq;

        if (copy_from_user(&args, (void __user *)arg, sizeof(args))) {
            return -EFAULT;
        }

        /* Update seq in the command header */
        struct henix_cmd_hdr *hdr = (struct henix_cmd_hdr *)args.data;
        hdr->seq = hdev->next_seq++;
        seq = hdr->seq;

        /* Copy command to device SRAM */
        u32 tail = readl(hdev->mmio + REG_CMD_TAIL);
        u32 head = readl(hdev->mmio + REG_CMD_HEAD);
        u32 slot = tail % HENIX_CMD_DEPTH;
        u32 offset = slot * HENIX_CMD_SIZE;

        dev_info(hdev->dev, "head=%u, tail=%u, slot=%u, seq=%u\n", head, tail, slot, seq);

        memcpy_toio(hdev->mmio + REG_CMD_SRAM + offset, args.data, HENIX_CMD_SIZE);

        /* Ensure command is visible to device */
        dma_wmb();

        /* Update tail */
        writel(tail + 1, hdev->mmio + REG_CMD_TAIL);
        dev_info(hdev->dev, "new_tail=%u\n", tail + 1);

        /* Ring doorbell */
        writel(1, hdev->mmio + REG_CMD_DOORBELL);

        /* Update args with seq */
        args.seq = seq;
        if (copy_to_user((void __user *)arg, &args, sizeof(args))) {
            return -EFAULT;
        }

        /* blocking unless O_NONBLOCK */
        if (!(filp->f_flags & O_NONBLOCK)) {
            dev_info(hdev->dev, "Waiting for seq %u\n", seq);
            ret = wait_event_interruptible(
                hdev->wq,
                READ_ONCE(hdev->completed_seq) >= seq);
            if (ret) {
                return ret;
            }
        }

        return 0;
    }

    default:
        return -ENOTTY;
    }
}

static __poll_t henix_poll(struct file *filp,
                           struct poll_table_struct *wait)
{
    struct henix_dev *hdev = filp->private_data;
    __poll_t mask = 0;

    poll_wait(filp, &hdev->wq, wait);

    if (READ_ONCE(hdev->completed_seq) ==
        READ_ONCE(hdev->next_seq))
        mask |= POLLOUT | POLLWRNORM;
    else
        mask |= POLLIN | POLLRDNORM;

    return mask;
}



static const struct file_operations henix_buf_fops = {
    .owner          = THIS_MODULE,
    .mmap           = henix_buf_mmap,
    .release        = henix_buf_release,
    .llseek         = noop_llseek,
};

static const struct file_operations henix_fops = {
    .owner          = THIS_MODULE,
    .open           = henix_open,
    .unlocked_ioctl = henix_ioctl,
    .poll           = henix_poll,
    .llseek         = noop_llseek,
};

static void henix_remove(struct platform_device *pdev)
{
    struct henix_dev *hdev = platform_get_drvdata(pdev);
    int i;

    writel(0, hdev->mmio + REG_IRQ_ENABLE);
    misc_deregister(&hdev->miscdev);

    /* Free all allocated buffers */
    for (i = 0; i < HENIX_BUF_TABLE_SIZE; i++) {
        if (hdev->buf_ptrs[i]) {
            struct henix_buffer *buf = hdev->buf_ptrs[i];
            dma_free_coherent(hdev->dev, buf->size, 
                             buf->cpu_addr, 
                             buf->dma_addr);
            kfree(buf);
        }
    }

    /* Free buffer table */
    if (hdev->buf_table) {
        dma_free_coherent(hdev->dev, sizeof(*hdev->buf_table) * HENIX_BUF_TABLE_SIZE, 
                         hdev->buf_table, hdev->buf_table_dma);
    }
}

static const struct of_device_id henix_of_match[] = {
    { .compatible = "henix,npu" },
    {}
};
MODULE_DEVICE_TABLE(of, henix_of_match);

static struct platform_driver henix_driver = {
    .probe  = henix_probe,
    .remove = henix_remove,
    .driver = {
        .name = "henix-npu",
        .of_match_table = henix_of_match,
    },
};

module_platform_driver(henix_driver);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Henix NPU Command Processor Driver");
MODULE_AUTHOR("Henix");
MODULE_VERSION("1.0");
