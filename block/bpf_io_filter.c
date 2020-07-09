#include <linux/bpf_io_filter.h>

#include <linux/bpf.h>
#include <linux/bpf_trace.h>
#include <linux/filter.h>
#include <linux/btf.h>
#include <linux/filter.h>
#include <linux/kallsyms.h>
#include <linux/bpf_verifier.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/genhd.h>
#include <uapi/linux/bpf.h>

#include "blk-bpf-io-filter.h"

/*
Need to build this out such that all, but only, necessary functions are
allowed.

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
	case BPF_FUNC_ktime_get_ns:
		return &bpf_ktime_get_ns_proto;
	case BPF_FUNC_tail_call:
		return &bpf_tail_call_proto;
	case BPF_FUNC_get_current_pid_tgid:
		return &bpf_get_current_pid_tgid_proto;
	case BPF_FUNC_get_current_task:
		return &bpf_get_current_task_proto;
	case BPF_FUNC_get_current_uid_gid:
		return &bpf_get_current_uid_gid_proto;
	case BPF_FUNC_get_current_comm:
		return &bpf_get_current_comm_proto;
	case BPF_FUNC_trace_printk:
		return bpf_get_trace_printk_proto();
	case BPF_FUNC_get_smp_processor_id:
		return &bpf_get_smp_processor_id_proto;
	case BPF_FUNC_get_numa_node_id:
		return &bpf_get_numa_node_id_proto;
	case BPF_FUNC_perf_event_read:
		return &bpf_perf_event_read_proto;
	case BPF_FUNC_probe_write_user:
		return bpf_get_probe_write_proto();
	case BPF_FUNC_current_task_under_cgroup:
		return &bpf_current_task_under_cgroup_proto;
	case BPF_FUNC_get_prandom_u32:
		return &bpf_get_prandom_u32_proto;
	case BPF_FUNC_probe_read_user:
		return &bpf_probe_read_user_proto;
	case BPF_FUNC_probe_read_kernel:
		return &bpf_probe_read_kernel_proto;
	case BPF_FUNC_probe_read:
		return &bpf_probe_read_compat_proto;
	case BPF_FUNC_probe_read_user_str:
		return &bpf_probe_read_user_str_proto;
	case BPF_FUNC_probe_read_kernel_str:
		return &bpf_probe_read_kernel_str_proto;
	case BPF_FUNC_probe_read_str:
		return &bpf_probe_read_compat_str_proto;
#ifdef CONFIG_CGROUPS
	case BPF_FUNC_get_current_cgroup_id:
		return &bpf_get_current_cgroup_id_proto;
#endif
	case BPF_FUNC_send_signal:
		return &bpf_send_signal_proto;
	case BPF_FUNC_perf_event_output:
		return &bpf_perf_event_output_proto;
	case BPF_FUNC_get_stackid:
		return &bpf_get_stackid_proto;
	case BPF_FUNC_get_stack:
		return &bpf_get_stack_proto;
	case BPF_FUNC_perf_event_read_value:
		return &bpf_perf_event_read_value_proto;
#ifdef CONFIG_BPF_KPROBE_OVERRIDE
	case BPF_FUNC_override_return:
		return &bpf_override_return_proto;
#endif
	default:
		return NULL;
	}
}
*/

const struct bpf_prog_ops io_filter_prog_ops = {
};

const struct bpf_verifier_ops io_filter_verifier_ops = {
	.get_func_proto = bpf_tracing_func_proto,
	.is_valid_access = btf_ctx_access,
};


int io_filter_prog_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
	struct gendisk *disk;
	struct fd f;

	if (attr->attach_flags)
		return -EINVAL;

	f = fdget(attr->target_fd);
	if (!f.file)
		return -EBADF;

	disk  = I_BDEV(f.file->f_mapping->host)->bd_disk;
	if (disk == NULL)
		return -ENXIO;

	//TODO: change to array of programs to allow multiple programs to attach
	rcu_assign_pointer(disk->prog, prog);

	return 0;
}

int io_filter_prog_detach(const union bpf_attr *attr)
{
	struct bpf_prog *prog;
	struct gendisk *disk;
	struct fd f;

	if (attr->attach_flags)
		return -EINVAL;

	prog = bpf_prog_get_type(attr->attach_bpf_fd,
				 BPF_PROG_TYPE_IO_FILTER);

	if (IS_ERR(prog))
		return PTR_ERR(prog);

	f = fdget(attr->target_fd);
	if (!f.file)
		return -EBADF;

	disk  = I_BDEV(f.file->f_mapping->host)->bd_disk;
	if (disk == NULL)
		return -ENXIO;

	rcu_assign_pointer(disk->prog, NULL);

	bpf_prog_put(prog);

	return 0;
}

int io_filter_bpf_run(struct bio *bio)
{
	struct bpf_prog *prog;
	int ret = 0;

	rcu_read_lock();
	prog = rcu_dereference(bio->bi_disk->prog);
	if (prog)
		ret = BPF_PROG_RUN(prog, bio);
	rcu_read_unlock();

	return ret;       /* allow io by default */
}
