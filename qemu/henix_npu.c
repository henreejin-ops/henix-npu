#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/thread.h"
#include "system/address-spaces.h"
#include "hw/core/irq.h"
#include "hw/core/sysbus.h"
#include "henix_npu.h"
#include "henix_def.h"

/* ---------------- Registers ---------------- */

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

/* ---------------- Commands ---------------- */

/* ---------------- Buffer Table ---------------- */

typedef struct HenixBufferDesc {
    uint64_t addr;
    uint32_t size;
    uint32_t flags;
} HenixBufferDesc;

/* ---------------- Device State ---------------- */

struct HenixNPUState {
    SysBusDevice parent_obj;

    MemoryRegion mmio;
    qemu_irq irq;

    uint8_t  cmd_sram[HENIX_NPU_CMD_SRAM_SIZE];
    uint32_t head;
    uint32_t tail;
    uint32_t completed_seq;

    uint32_t irq_status;
    uint32_t irq_enable;

    uint64_t bt_base;
    uint32_t bt_size;
    HenixBufferDesc *bt_cache;
    uint32_t bt_cache_size;
    bool bt_valid;

    AddressSpace *as;
};

/* ---------------- IRQ ---------------- */

static void henix_raise_irq(HenixNPUState *s)
{
    if (s->irq_enable && !s->irq_status) {
        s->irq_status = 1;
        qemu_irq_raise(s->irq);
    }
}

/* ---------------- Buffer Table Access ---------------- */

static bool henix_load_buf_desc(HenixNPUState *s,
                                uint32_t idx,
                                HenixBufferDesc *out)
{
    if (!s->bt_valid || idx >= s->bt_cache_size) {
        return false;
    }

    *out = s->bt_cache[idx];
    return true;
}

static void henix_reload_buffer_table(HenixNPUState *s)
{
    qemu_log("henix: reloading buffer table - base=0x%"PRIx64", size=%u\n",
        s->bt_base, s->bt_size);

    g_free(s->bt_cache);

    if (s->bt_size == 0 || s->bt_base == 0) {
        s->bt_cache = NULL;
        s->bt_cache_size = 0;
        s->bt_valid = false;
        qemu_log("henix: buffer table invalid (base or size is zero), cache cleared\n");
        return;
    }

    s->bt_cache_size = s->bt_size;
    s->bt_cache = g_malloc0(sizeof(HenixBufferDesc) * s->bt_size);

    address_space_read(s->as,
        s->bt_base,
        MEMTXATTRS_UNSPECIFIED,
        s->bt_cache,
        sizeof(HenixBufferDesc) * s->bt_size);

    s->bt_valid = true;
    qemu_log("henix: buffer table loaded successfully, %u entries cached\n",
        s->bt_cache_size);
}

/* ---------------- Execute Memcpy ---------------- */

static void henix_exec_memcpy(HenixNPUState *s, struct henix_cmd_memcpy *cmd)
{
    HenixBufferDesc src, dst;
    uint8_t *tmp;

    qemu_log("henix: executing memcpy command - seq=%u, src_buf=%u, dst_buf=%u, len=%u\n",
        cmd->hdr.seq, cmd->src_buf, cmd->dst_buf, cmd->len);

    if (!henix_load_buf_desc(s, cmd->src_buf, &src)) {
        qemu_log("henix: invalid source buffer index %u\n", cmd->src_buf);
        return;
    }
    if (!henix_load_buf_desc(s, cmd->dst_buf, &dst)) {
        qemu_log("henix: invalid destination buffer index %u\n", cmd->dst_buf);
        return;
    }

    if (cmd->len > src.size || cmd->len > dst.size) {
        qemu_log("henix: memcpy length %u exceeds buffer size (src=%u, dst=%u)\n",
            cmd->len, src.size, dst.size);
        return;
    }

    tmp = g_malloc(cmd->len);

    address_space_read(s->as, src.addr,
                       MEMTXATTRS_UNSPECIFIED,
                       tmp, cmd->len);

    address_space_write(s->as, dst.addr,
                        MEMTXATTRS_UNSPECIFIED,
                        tmp, cmd->len);

    g_free(tmp);

    qemu_log("henix: memcpy completed - seq=%u, copied %u bytes from 0x%"PRIx64" to 0x%"PRIx64"\n",
        cmd->hdr.seq, cmd->len, src.addr, dst.addr);
}

/* ---------------- Execute Matmul ---------------- */

static void henix_exec_matmul(HenixNPUState *s, struct henix_cmd_matmul *cmd)
{
    HenixBufferDesc a_buf, b_buf, c_buf;
    float *A, *B, *C;
    uint32_t i, j, k;

    qemu_log("henix: executing matmul command - seq=%u, M=%u, K=%u, N=%u, a_buf=%u, b_buf=%u, c_buf=%u\n",
        cmd->hdr.seq, cmd->M, cmd->K, cmd->N, cmd->a_buf, cmd->b_buf, cmd->c_buf);

    if (!henix_load_buf_desc(s, cmd->a_buf, &a_buf)) {
        qemu_log("henix: invalid A buffer index %u\n", cmd->a_buf);
        return;
    }
    if (!henix_load_buf_desc(s, cmd->b_buf, &b_buf)) {
        qemu_log("henix: invalid B buffer index %u\n", cmd->b_buf);
        return;
    }
    if (!henix_load_buf_desc(s, cmd->c_buf, &c_buf)) {
        qemu_log("henix: invalid C buffer index %u\n", cmd->c_buf);
        return;
    }

    // Allocate temporary buffers
    A = g_malloc(cmd->M * cmd->K * sizeof(float));
    B = g_malloc(cmd->K * cmd->N * sizeof(float));
    C = g_malloc(cmd->M * cmd->N * sizeof(float));

    // Read matrices from memory
    address_space_read(s->as, a_buf.addr, MEMTXATTRS_UNSPECIFIED, A, cmd->M * cmd->K * sizeof(float));
    address_space_read(s->as, b_buf.addr, MEMTXATTRS_UNSPECIFIED, B, cmd->K * cmd->N * sizeof(float));

    // Compute C = A × B
    for (i = 0; i < cmd->M; i++) {
        for (j = 0; j < cmd->N; j++) {
            float sum = 0.0f;
            for (k = 0; k < cmd->K; k++) {
                sum += A[i * cmd->K + k] * B[k * cmd->N + j];
            }
            C[i * cmd->N + j] = sum;
        }
    }

    // Write result back to memory
    address_space_write(s->as, c_buf.addr, MEMTXATTRS_UNSPECIFIED, C, cmd->M * cmd->N * sizeof(float));

    // Free temporary buffers
    g_free(A);
    g_free(B);
    g_free(C);

    qemu_log("henix: matmul completed - seq=%u\n", cmd->hdr.seq);
}

/* ---------------- Command Processor ---------------- */

static void henix_process_commands(HenixNPUState *s)
{
    if (!s->bt_valid) {
        qemu_log("henix: buffer table not loaded\n");
        return;
    }

    uint32_t initial_head = s->head;
    // uint32_t commands_to_process = (s->tail - s->head) % HENIX_NPU_CMD_DEPTH;
    uint32_t commands_to_process = s->tail - s->head;


    
    if (commands_to_process == 0) {
        return;
    }

    qemu_log("henix: starting command processing - head=0x%x, tail=0x%x, commands_to_process=%u\n",
        s->head, s->tail, commands_to_process);

    while (s->head != s->tail) {
        uint32_t idx = s->head % HENIX_NPU_CMD_DEPTH;
        struct henix_cmd_hdr *cmd_hdr = (struct henix_cmd_hdr *)
            (s->cmd_sram + idx * HENIX_CMD_SLOT_SIZE);

        qemu_log("henix: processing command - idx=%u, opcode=%u, seq=%u\n",
            idx, cmd_hdr->opcode, cmd_hdr->seq);

        switch (cmd_hdr->opcode) {
        case HENIX_CMD_MEMCPY:
            henix_exec_memcpy(s, (struct henix_cmd_memcpy *)cmd_hdr);
            break;
        case HENIX_CMD_MATMUL:
            henix_exec_matmul(s, (struct henix_cmd_matmul *)cmd_hdr);
            break;
        default:
            qemu_log("henix: unknown command opcode %u\n", cmd_hdr->opcode);
            break;
        }

        s->completed_seq = cmd_hdr->seq;
        s->head++;
        qemu_log("henix: command completed - seq=%u, new_head=0x%x\n",
            cmd_hdr->seq, s->head);
    }

    qemu_log("henix: command processing completed - processed %u commands\n",
        s->head - initial_head);

    henix_raise_irq(s);
}

/* ---------------- MMIO ---------------- */

static uint64_t henix_mmio_read(void *opaque,
                               hwaddr off,
                               unsigned size)
{
    HenixNPUState *s = opaque;

    if (off < HENIX_NPU_CMD_SRAM_SIZE) {
        uint64_t v = 0;
        memcpy(&v, s->cmd_sram + off, size);
        return v;
    }

    switch (off) {
    case REG_CMD_HEAD:        return s->head;
    case REG_CMD_TAIL:        return s->tail;
    case REG_IRQ_STATUS:      return s->irq_status;
    case REG_IRQ_ENABLE:      return s->irq_enable;
    case REG_COMPLETED_SEQ:   return s->completed_seq;
    case REG_BT_BASE_LO:      return (uint32_t)s->bt_base;
    case REG_BT_BASE_HI:      return (uint32_t)(s->bt_base >> 32);
    case REG_BT_SIZE:         return s->bt_size;
    default:
        return 0;
    }
}

static void henix_mmio_write(void *opaque,
                            hwaddr off,
                            uint64_t val,
                            unsigned size)
{
    HenixNPUState *s = opaque;

    if (off < HENIX_NPU_CMD_SRAM_SIZE) {
        memcpy(s->cmd_sram + off, &val, size);
        return;
    }

    qemu_log("henix: MMIO write offset=0x%"HWADDR_PRIx" value=0x%"PRIx64"\n", off, val);

    switch (off) {
    case REG_CMD_TAIL:
        qemu_log("henix: writing CMD_TAIL - old=0x%x, new=0x%"PRIx64"\n",
            s->tail, val);
        s->tail = val;
        break;

    case REG_CMD_DOORBELL:
        qemu_log("henix: writing CMD_DOORBELL (kick) - val=0x%"PRIx64"\n", val);
        henix_process_commands(s);
        break;

    case REG_IRQ_ENABLE:
        qemu_log("henix: writing IRQ_ENABLE - old=0x%x, new=0x%"PRIx64"\n",
            s->irq_enable, val);
        s->irq_enable = val & 1;
        break;

    case REG_IRQ_ACK:
        qemu_log("henix: writing IRQ_ACK - val=0x%"PRIx64"\n", val);
        s->irq_status = 0;
        qemu_irq_lower(s->irq);
        break;

    case REG_BT_BASE_LO:
        qemu_log("henix: writing BT_BASE_LO - old=0x%x, new=0x%"PRIx64"\n",
            (uint32_t)s->bt_base, val);
        s->bt_base = (s->bt_base & 0xffffffff00000000ULL) | val;
        break;

    case REG_BT_BASE_HI:
        qemu_log("henix: writing BT_BASE_HI - old=0x%x, new=0x%"PRIx64"\n",
            (uint32_t)(s->bt_base >> 32), val);
        s->bt_base = (s->bt_base & 0xffffffffULL) | (val << 32);
        break;

    case REG_BT_SIZE:
        qemu_log("henix: writing BT_SIZE - old=0x%x, new=0x%"PRIx64"\n",
            s->bt_size, val);
        s->bt_size = val;
        break;

    case REG_BT_RELOAD:
        qemu_log("henix: writing BT_RELOAD - val=0x%"PRIx64"\n", val);
        henix_reload_buffer_table(s);
        break;

    default:
        break;
    }
}

static const MemoryRegionOps henix_mmio_ops = {
    .read = henix_mmio_read,
    .write = henix_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

/* ---------------- Lifecycle ---------------- */

static void henix_reset(DeviceState *dev)
{
    HenixNPUState *s = HENIX_NPU(dev);

    qemu_log("henix: resetting device - clearing all state\n");

    s->head = 0;
    s->tail = 0;
    s->completed_seq = 0;
    s->irq_status = 0;
    s->irq_enable = 0;
    s->bt_base = 0;
    s->bt_size = 0;
    s->bt_valid = false;
    g_free(s->bt_cache);
    s->bt_cache = NULL;
    s->bt_cache_size = 0;

    memset(s->cmd_sram, 0, sizeof(s->cmd_sram));

    qemu_log("henix: device reset completed\n");
}

static void henix_init(Object *obj)
{
    HenixNPUState *s = HENIX_NPU(obj);

    memory_region_init_io(&s->mmio, obj,
                          &henix_mmio_ops,
                          s,
                          "henix-npu",
                          HENIX_NPU_MMIO_SIZE);

    sysbus_init_mmio(SYS_BUS_DEVICE(obj), &s->mmio);
    sysbus_init_irq(SYS_BUS_DEVICE(obj), &s->irq);
}

static void henix_realize(DeviceState *dev, Error **errp)
{
    HenixNPUState *s = HENIX_NPU(dev);
    s->as = &address_space_memory;
}

static void henix_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->legacy_reset = henix_reset;
    dc->realize = henix_realize;
}

static const TypeInfo henix_info = {
    .name          = TYPE_HENIX_NPU,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(HenixNPUState),
    .instance_init = henix_init,
    .class_init    = henix_class_init,
};

static void henix_register(void)
{
    type_register_static(&henix_info);
}

type_init(henix_register)
