======================
IO Filtering with eBPF
======================

Bio requests can be filtered with the eBPF IO filter program type.

Attachment
==========

IO filter programs can be attached to disks. Up to 64 filter programs can be attached to a single disk. References to the attached programs are stored in the gendisk struct as a bpf_prog_array.

API
===

Data is passed between the userspace and kernel eBPF code via a new struct bpf_io_request. This struct contains three fields: sector_start (starting sector of the bio request), sector_cnt (size of the request in sectors), and opf (operation information, opf field from the bio).

Hook
====

The eBPF programs for a given disk are run whenever a bio request is submitted to that disk. The eBPF programs return IO_BLOCK or IO_ALLOW. If any of the programs return IO_BLOCK, the bio request is blocked.

Example
=======

An example, protect_gpt, is provided in the /samples/bpf/ folder. This sample uses an IO filter program to protect the GUID partition table by preventing writes to the first 34 sectors.

