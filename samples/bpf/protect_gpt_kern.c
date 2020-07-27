#include <linux/bpf.h>
#include <linux/blk_types.h>
#include "bpf/bpf_helpers.h"

char _license[] SEC("license") = "GPL";

#define GPT_SECTORS 34

SEC("gpt_io_filter")
int protect_gpt(struct bpf_io_request *io_req)
{
	/* within GPT and not a read operation */
	if (io_req->sector_start < GPT_SECTORS && (io_req->opf & REQ_OP_MASK) != REQ_OP_READ)
		return IO_BLOCK;

	return IO_ALLOW;
}


