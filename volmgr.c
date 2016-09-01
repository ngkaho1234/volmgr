#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <dirent.h>
#include <pthread.h>
#include <linux/netlink.h>

enum {
	VOLMGR_RCVBUF = 2 * 1024 * 1024
};

/*
 * Copied from android_system_vold so that the
 * behavior will be similar to vold...
 */
static void volmgr_do_coldboot(DIR *d, int lvl)
{
	struct dirent *de;
	int dfd, fd;

	dfd = dirfd(d);

	fd = openat(dfd, "uevent", O_WRONLY | O_CLOEXEC);
	if(fd >= 0) {
		write(fd, "add\n", 4);
		close(fd);
	}

	while((de = readdir(d))) {
		DIR *d2;

		if (de->d_name[0] == '.')
			continue;

		if (de->d_type != DT_DIR && lvl > 0)
			continue;

		fd = openat(dfd, de->d_name, O_RDONLY | O_DIRECTORY);
		if(fd < 0)
			continue;

		d2 = fdopendir(fd);
		if(d2 == 0)
			close(fd);
		else {
			volmgr_do_coldboot(d2, lvl + 1);
			closedir(d2);
		}
	}
}

void volmgr_coldboot(const char *path)
{
	DIR *d = opendir(path);
	if(d) {
		volmgr_do_coldboot(d, 0);
		closedir(d);
	}
}

static void *volmgr_coldboot_pthread_routine(const char *path)
{
	volmgr_coldboot((char *)path);
	return NULL;
}

static int volmgr_coldboot_threaded(char *path, pthread_t *thr)
{
	return pthread_create(
			thr,
			NULL,
			(void *(*)(void *))volmgr_coldboot_pthread_routine,
			path);
}

static void volmgr_coldboot_threaded_wait(pthread_t thr)
{
	pthread_join(thr, NULL);
}

int main(int argc, char **argv)
{
	pthread_t thr;
	volmgr_coldboot_threaded("/sys/block", &thr);
	volmgr_coldboot_threaded_wait(thr);
	return EXIT_SUCCESS;
}
