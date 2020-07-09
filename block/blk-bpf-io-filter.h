
#ifndef _BLK_BPF_IO_FILTER
#define _BLK_BPF_IO_FILTER

#ifdef CONFIG_BPF_IO_FILTER
int io_filter_bpf_run(struct bio *bio);
#else
static inline int io_filter_bpf_run(struct bio *bio) { return 0; }
#endif

#endif	/* _BLK_BPF_IO_FILTER */


