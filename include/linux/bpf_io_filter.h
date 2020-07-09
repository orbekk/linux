#ifndef _BPF_IO_FILTER_H
#define _BPF_IO_FILTER_H

#include <uapi/linux/bpf.h>
struct bpf_prog;

#ifdef CONFIG_BPF_IO_FILTER
int io_filter_prog_attach(const union bpf_attr *attr, struct bpf_prog *prog);
int io_filter_prog_detach(const union bpf_attr *attr);
#else
static inline int io_filter_prog_attach(const union bpf_attr *attr,
					struct bpf_prog *prog)
{
	return -EINVAL;
}
static inline int io_filter_prog_detach(const union bpf_attr *attr)
{
	return -EINVAL;
}
#endif
#endif /* _BPF_IO_FILTER_H */
