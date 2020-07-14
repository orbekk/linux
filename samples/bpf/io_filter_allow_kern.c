#include <linux/bpf.h>
#include "bpf/bpf_helpers.h"
#include <linux/bio.h>

char _license[] SEC("license") = "GPL";

SEC("io_filter")
int filter_io(struct bpf_io_request *io_req)
{
	return IO_ALLOW;
}

