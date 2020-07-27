#include <linux/bpf_io_filter.h>

#include <linux/bpf.h>
#include <linux/bpf_trace.h>
#include <linux/filter.h>
#include <linux/kallsyms.h>
#include <linux/bpf_verifier.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/genhd.h>
#include <uapi/linux/bpf.h>
#include <linux/bio.h>

#include "blk-bpf-io-filter.h"

#define io_filter_rcu_dereference_progs(disk)	\
	rcu_dereference_protected(disk->progs, lockdep_is_held(&disk->io_filter_lock))

static const struct bpf_func_proto *
io_filter_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_map_lookup_elem:
		return &bpf_map_lookup_elem_proto;
	case BPF_FUNC_map_update_elem:
		return &bpf_map_update_elem_proto;
	case BPF_FUNC_map_delete_elem:
		return &bpf_map_delete_elem_proto;
	case BPF_FUNC_map_push_elem:
		return &bpf_map_push_elem_proto;
	case BPF_FUNC_map_pop_elem:
		return &bpf_map_pop_elem_proto;
	case BPF_FUNC_map_peek_elem:
		return &bpf_map_peek_elem_proto;
	case BPF_FUNC_trace_printk:
		if (capable(CAP_SYS_ADMIN))
			return bpf_get_trace_printk_proto();
		/* else fall through */
	default:
		return NULL;
	}
}


const struct bpf_prog_ops io_filter_prog_ops = {
};

static bool io_filter_is_valid_access(int off, int size,
				      enum bpf_access_type type,
				      const struct bpf_prog *prog,
				      struct bpf_insn_access_aux *info)
{
	const __u32 size_default = sizeof(__u32);

	if (type != BPF_READ)
		return false;

	if (off < 0 || off >= offsetofend(struct bpf_io_request, opf))
		return false;

	if (off % size != 0)
		return false;

	switch(off) {
	case offsetof(struct bpf_io_request, sector_start):
		return size == sizeof(__u64);
	case offsetof(struct bpf_io_request, sector_cnt):
		return size == sizeof(__u32);
	case bpf_ctx_range(struct bpf_io_request, opf):
		bpf_ctx_record_field_size(info, size_default);
		return bpf_ctx_narrow_access_ok(off, size, size_default);
	default:
		return false;
	}
}

const struct bpf_verifier_ops io_filter_verifier_ops = {
	.get_func_proto = io_filter_func_proto,
	.is_valid_access = io_filter_is_valid_access,
};

#define BPF_MAX_PROGS 64

int io_filter_prog_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
	struct gendisk *disk;
	struct fd f;
	struct bpf_prog_array *old_array;
	struct bpf_prog_array *new_array;
	int ret;

	if (attr->attach_flags)
		return -EINVAL;

	f = fdget(attr->target_fd);
	if (!f.file)
		return -EBADF;

	disk  = I_BDEV(f.file->f_mapping->host)->bd_disk;
	if (disk == NULL)
		return -ENXIO;

	ret = mutex_lock_interruptible(&disk->io_filter_lock);
	if (ret)
		return ret;

	old_array = io_filter_rcu_dereference_progs(disk);
	if (old_array && bpf_prog_array_length(old_array) >= BPF_MAX_PROGS) {
		ret = -E2BIG;
		goto unlock;
	}

	ret = bpf_prog_array_copy(old_array, NULL, prog, &new_array);
	if (ret < 0)
		goto unlock;

	rcu_assign_pointer(disk->progs, new_array);
	bpf_prog_array_free(old_array);

unlock:
	mutex_unlock(&disk->io_filter_lock);
	return ret;
}

int io_filter_prog_detach(const union bpf_attr *attr)
{
	struct bpf_prog *prog;
	struct gendisk *disk;
	struct fd f;
	struct bpf_prog_array *old_array;
	struct bpf_prog_array *new_array;
	int ret;

	if (attr->attach_flags)
		return -EINVAL;

	/* increments prog refcnt */
	prog = bpf_prog_get_type(attr->attach_bpf_fd,
				 BPF_PROG_TYPE_IO_FILTER);

	if (IS_ERR(prog))
		return PTR_ERR(prog);

	f = fdget(attr->target_fd);
	if (!f.file) {
		ret = -EBADF;
		goto put;
	}

	disk  = I_BDEV(f.file->f_mapping->host)->bd_disk;
	if (disk == NULL) {
		ret = -ENXIO;
		goto put;
	}

	ret = mutex_lock_interruptible(&disk->io_filter_lock);
	if (ret)
		goto put;

	old_array = io_filter_rcu_dereference_progs(disk);
	ret = bpf_prog_array_copy(old_array, prog, NULL, &new_array);
	if (ret)
		goto unlock;

	rcu_assign_pointer(disk->progs, new_array);
	bpf_prog_array_free(old_array);
	bpf_prog_put(prog);	/* put for detaching of program from dev */

unlock:
	mutex_unlock(&disk->io_filter_lock);
put:
	bpf_prog_put(prog);	/* put for bpf_prog_get_type */
	return ret;
}

int io_filter_bpf_run(struct bio *bio)
{
	struct bpf_io_request io_req = {
		.sector_start = bio->bi_iter.bi_sector,
		.sector_cnt = bio_sectors(bio),
		.opf = bio->bi_opf,
	};

	/* allow io by default */
	return BPF_PROG_RUN_ARRAY_CHECK(bio->bi_disk->progs, &io_req, BPF_PROG_RUN);
}

void io_filter_bpf_free(struct gendisk *disk)
{
	struct bpf_prog_array_item *item;
	struct bpf_prog_array *array;

	array = io_filter_rcu_dereference_progs(disk);
	if (!array)
		return;

	for (item = array->items; item->prog; item++)
		bpf_prog_put(item->prog);

	bpf_prog_array_free(array);
}
