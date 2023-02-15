#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

/**
 * nsenter enters into the hard-coded network namespace that has a file mount
 * at /run/netns/rd1
 */
void nsenter(void)
{
    int fd = open("/run/netns/rd1", O_RDONLY);
    if (fd < 0)
    {
        fprintf(stderr, "failed to open namespace: %d\n", fd);
        abort();
    }

    if (setns(fd, CLONE_NEWNET) != 0)
    {
        fprintf(stderr, "failed to set namespace: %d\n", errno);
        abort();
    }

    if (close(fd) != 0)
    {
        fprintf(stderr, "failed to close fd: %d\n", errno);
        abort();
    }
}