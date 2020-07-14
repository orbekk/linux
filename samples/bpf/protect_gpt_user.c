#define _GNU_SOURCE

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <errno.h>
#include "trace_helpers.h"
#include "bpf_load.h"

/*
 * user program to load bpf program (protect_gpt_kern) to prevent writing to GUID
 * parititon table
 *
 * argument 1: device where program will be attached (ie. /dev/sda)
 * argument 2: name for pinned program
 * argument 3: --attach or --detach to attach/detach program
*/

int attach(char* dev, char* path);
int detach(char* dev, char* path);
void usage(char* exec);

int main(int argc, char **argv)
{
	char path[256];

	if (argc != 4){
		usage(argv[0]);
		return 1;
	}

	strcpy(path, "/sys/fs/bpf/");
	strcat(path, argv[2]);

	if (strcmp(argv[3], "--attach") == 0)
		return attach(argv[1], path);
	else if (strcmp(argv[3], "--detach") == 0)
		return detach(argv[1], path);
	else {
		fprintf(stderr, "Error: invalid flag, please specify --attach or --detach");
		return 1;
	}

	return 1;
}

int attach(char* dev, char* path)
{
	struct bpf_object *obj;
	int ret, devfd, progfd;

	progfd = bpf_obj_get(path);
	if (progfd >= 0) {
		fprintf(stderr, "Error: object already pinned at given location (%s)\n", path);
		return 1;
	}

	ret = bpf_prog_load("protect_gpt_kern.o",
			    BPF_PROG_TYPE_IO_FILTER, &obj, &progfd);
	if (ret) {
		fprintf(stderr, "Error: failed to load program\n");
		return 1;
	}

	devfd = open(dev, O_RDONLY);
	if (devfd == -1) {
		fprintf(stderr, "Error: failed to open block device %s\n", dev);
		return 1;
	}

	ret = bpf_prog_attach(progfd, devfd, BPF_BIO_SUBMIT, 0);
	if (ret) {
		fprintf(stderr, "Error: failed to attach program to device\n");
		close(devfd);
		return 1;
	}

	ret = bpf_obj_pin(progfd, path);
	if (ret != 0) {
		fprintf(stderr, "Error pinning program: %s\n", strerror(errno));
		fprintf(stderr, "Detaching program from device\n");

		if(bpf_prog_detach2(progfd, devfd, BPF_BIO_SUBMIT))
			fprintf(stderr, "Error: failed to detach program\n");

		close(devfd);
		return 1;
	}

	close(devfd);
	printf("Attached protect_gpt program to device %s.\n", dev);
	printf("Program pinned to %s.\n", path);
	return 0;
}

int detach(char* dev, char* path)
{
	int ret, devfd, progfd;

	progfd = bpf_obj_get(path);
	if (progfd < 0) {
		fprintf(stderr, "Error: failed to get pinned program from path %s\n", path);
		return 1;
	}

	devfd = open(dev, O_RDONLY);
	if (devfd == -1) {
		fprintf(stderr, "Error: failed to open block device %s\n", dev);
		return 1;
	}

	ret = bpf_prog_detach2(progfd, devfd, BPF_BIO_SUBMIT);
	if (ret) {
		fprintf(stderr, "Error: failed to detach program\n");
		close(devfd);
		return 1;
	}

	close(devfd);

	ret = unlink(path);
	if (ret < 0) {
		fprintf(stderr, "Error unpinning map at %s: %s\n", path, strerror(errno));
		return 1;
	}

	printf("Detached and unpinned program.\n");
	return 0;
}

void usage(char* exec)
{
	printf("Usage:\n");
	printf("\t %s <device> <prog name> --attach\n", exec);
	printf("\t %s <device> <prog name> --detach\n", exec);
}
