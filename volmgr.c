#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <linux/netlink.h>

#include <uv.h>

enum {
	VOLMGR_RCVBUF = 2 * 1024 * 1024
};

struct volmgr_token {
	char *key;
	char *value;
	struct volmgr_token *next;
};

#define for_each_volmgr_token(pos, n, vtok) \
	for ((pos) = (vtok);	\
		(n) = (pos)?(pos)->next:NULL, (pos);	\
		(pos) = (n))

static void volmgr_token_destroy(struct volmgr_token *vtok)
{
	struct volmgr_token *ptr, *tmp;
	for_each_volmgr_token(ptr, tmp, vtok) {
		free(ptr->key);
		free(ptr->value);
		free(ptr);
	}
}

static struct volmgr_token *
volmgr_token_build(const char *buf, size_t bufsz)
{
	struct volmgr_token *vtok = NULL;
	size_t sz_rem = bufsz;
	size_t str_len;

	/* Skip the first string */
	str_len = strnlen(buf, bufsz);
	sz_rem -= str_len;
	
	while (sz_rem) {
		
	}
	return vtok;
}

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

static char *volmgr_buf;

static void volmgr_poll_cb(
		uv_poll_t* handle,
		int status,
		int events)
{
	int fd;
	int nread, i;
	assert(!uv_fileno((uv_handle_t *)handle, &fd));
	nread = recv(fd, volmgr_buf, VOLMGR_RCVBUF, 0);
	assert(nread);
	if (nread < 0) {
		if (errno != EAGAIN)
			uv_stop(handle->loop);

		return;
	}
	for (i = 0;i < nread;i++) {
		if (volmgr_buf[i] == 0)
			putchar('\n');
		else
			putchar(volmgr_buf[i]);
	}
	putchar('\n');
}

int volmgr_loop()
{
	int ret = 0;
	int fd;
	int tmp;
	pthread_t thr;
	struct sockaddr_nl sa_nl;
	uv_loop_t *loop = uv_default_loop();
	uv_poll_t handle;
	sa_nl.nl_family = AF_NETLINK;
	sa_nl.nl_pad = 0;
	sa_nl.nl_pid = getpid();
	sa_nl.nl_groups = 1;

	fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
	if (fd < 0)
		return fd;

	ret = bind(
		fd,
		(struct sockaddr *)&sa_nl,
		sizeof(struct sockaddr));
	if (ret < 0)
		goto cleanup;

	tmp = VOLMGR_RCVBUF;
	ret = setsockopt(
			fd,
			SOL_SOCKET,
			SO_RCVBUF,
			&tmp,
			sizeof(tmp));
	if (ret < 0)
		goto cleanup;

	ret = setsockopt(
			fd,
			SOL_SOCKET,
			SO_RCVBUFFORCE,
			&tmp,
			sizeof(tmp));
	if (ret < 0)
		goto cleanup;

	uv_poll_init_socket(loop, &handle, fd);
	uv_poll_start(&handle, UV_READABLE, volmgr_poll_cb);
	volmgr_coldboot_threaded("/sys/block", &thr);
	uv_run(loop, UV_RUN_DEFAULT);
	volmgr_coldboot_threaded_wait(thr);
	uv_poll_stop(&handle);
cleanup:
	close(fd);
	return ret;
}

int main(int argc, char **argv)
{
	volmgr_buf = mmap(
			NULL,
			VOLMGR_RCVBUF,
			PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANON,
			-1,
			0);
	volmgr_loop();
	munmap(volmgr_buf, VOLMGR_RCVBUF);
	return EXIT_SUCCESS;
}
