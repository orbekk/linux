#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include "trace_helpers.h"
#include "bpf_load.h"

/*
 * argument 1: device where program will be attached (ie. /dev/sda)
 * argument 2: path where test file will be created to check IO
*/
int main(int argc, char **argv)
{
	struct bpf_object *obj;
	char filename[256];
	int fd, ret, progfd, devfd;

	if (argc != 3){
		printf("Invalid number of arguments\n");
		return 1;
	}

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

	ret = bpf_prog_load(filename,
			    BPF_PROG_TYPE_IO_FILTER, &obj, &progfd);

	if (ret) {
		printf("Failed to load program\n");
		return 1;
	}

	printf("Loaded io_filter program successfully.\n");

	devfd = open(argv[1], O_RDONLY);

	if (devfd == -1) {
		printf("Failed to open block device %s: %m\n", argv[1]);
		return 1;
	}

	fd = open(argv[2], O_WRONLY|O_CREAT|O_TRUNC, 0666);

	if (fd == -1) {
		printf("Failed to create test file %s\n", argv[2]);
		close(devfd);
		return 1;
	}

	printf("Opened file \"%s\" successfully.\n", argv[2]);

	ret = bpf_prog_attach(progfd, devfd, BPF_BIO_SUBMIT, 0);

	if (ret) {
		printf("Failed to attach bpf io_filter program to device: %m\n");
		close(devfd);
		close(fd);
		return 1;
	}

	printf("Attached bpf io_filter program to device\n");

	ret = write(fd, "bpf io_filter test write1 ", 26);

	if (ret == -1)
		printf("Failed to write to test file.\n");
	else
		printf("Wrote to test file.\n");

	ret = fsync(fd);

	if (ret == -1)
		printf("fsync failed.\n");
	else
		printf("fsync succeeded.\n");

	ret = bpf_prog_detach2(progfd, devfd, BPF_BIO_SUBMIT);

	if (ret) {
		printf("bpf_prog_detach2: returned %m\n");
		close(devfd);
		close(fd);
		return 1;
	}

	printf("Detached io_filter program from device.\n");

	ret = write(fd, "write2", 6);

	if (ret == -1)
		printf("Failed to write to test file.\n");
	else
		printf("Wrote to test file.\n");

	ret = fsync(fd);

	if (ret == -1)
		printf("fsync failed.\n");
	else
		printf("fsync succeeded.\n");

	close(fd);
	close(devfd);

	read_trace_pipe();

	printf("Exiting user program.\n");

	return 0;
}

