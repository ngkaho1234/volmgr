#include <assert.h>
#include <stdint.h>
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
#include <sys/stat.h>
#include <sys/mount.h>
#include <limits.h>
#include <linux/netlink.h>

#include <uv.h>
#include <blkid/blkid.h>

#define VOLMGR_DEV_PATH "/dev/block/volmgr"
#define VOLMGR_MOUNT_PATH "/storage/volmgr"

#define VOLMGR_DEV_PATH_MODE	\
		(S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)
#define VOLMGR_BLKDEV_MODE	\
		(S_IRUSR | S_IWUSR | S_IRGRP | S_IFBLK)
#define VOLMGR_MOUNT_PATH_MODE	\
		(S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)
#define VOLMGR_MOUNTPOINT_MODE	\
		(S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)

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
		if (ptr->key)
			free(ptr->key);
		if (ptr->value)
			free(ptr->value);
		free(ptr);
	}
}

static struct volmgr_token *
volmgr_token_build(const char *inbuf, size_t bufsz)
{
	struct volmgr_token *vtok = NULL, *vtok_ptr = NULL;
	struct volmgr_token *vtok_prev = NULL;
	size_t sz_rem = bufsz;
	size_t str_len;
	char *buf = malloc(bufsz), *buf_ptr;
	buf_ptr = buf;
	if (!buf)
		return NULL;
	memcpy(buf_ptr, inbuf, bufsz);

	/* Skip the first string */
	str_len = strnlen(buf_ptr, bufsz);
	sz_rem -= str_len + 1;
	buf_ptr += str_len + 1;
	
	while (sz_rem) {
		const char *tok = strtok(buf_ptr, "=");
		str_len = strnlen(tok, sz_rem);
		sz_rem -= str_len + 1;
		buf_ptr += str_len + 1;
		if (!vtok)
			vtok_ptr = vtok =
				malloc(sizeof(struct volmgr_token));
		else
			vtok_ptr =
				malloc(sizeof(struct volmgr_token));
		if (!vtok_ptr) {
			if (vtok)
				volmgr_token_destroy(vtok);

			vtok = NULL;
			goto out;
		}
		memset(vtok_ptr, 0, sizeof(struct volmgr_token));
		if (vtok_prev)
			vtok_prev->next = vtok_ptr;
		vtok_prev = vtok_ptr;

		vtok_ptr->key = malloc(str_len + 1);
		if (!vtok_ptr->key) {
			volmgr_token_destroy(vtok);
			vtok = NULL;
			goto out;
		}
		vtok_ptr->key[str_len] = 0;
		memcpy(vtok_ptr->key, tok, str_len);

		tok = strtok(NULL, "");
		str_len = strnlen(tok, sz_rem);
		sz_rem -= str_len + 1;
		buf_ptr += str_len + 1;

		vtok_ptr->value = malloc(str_len + 1);
		if (!vtok_ptr->value) {
			volmgr_token_destroy(vtok);
			vtok = NULL;
			goto out;
		}
		vtok_ptr->value[str_len] = 0;
		memcpy(vtok_ptr->value, tok, str_len);
	}
out:
	free(buf);
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

static void volmgr_mknod_work(uv_work_t *wi)
{

	int ret, i, nkeys;
	dev_t dev = (uintptr_t)wi->data;
	char dev_path[PATH_MAX], mountpoint[PATH_MAX];
	char *uuid_str, *type_str, *label_str;

	snprintf(dev_path, PATH_MAX, "%s/%u,%u", VOLMGR_DEV_PATH, major(dev), minor(dev));
	ret = mknod(
		dev_path,
		VOLMGR_BLKDEV_MODE,
		dev);
	if (ret < 0 && errno != EEXIST) {
		fprintf(stderr, "%s: mknod() failed. errno: %s\n",
			dev_path, strerror(errno));
		return;
	}

	uuid_str = blkid_get_tag_value(NULL, "UUID", dev_path);
	type_str = blkid_get_tag_value(NULL, "TYPE", dev_path);
	label_str = blkid_get_tag_value(NULL, "LABEL", dev_path);
	printf("dev_path: %s\n", dev_path);
	printf("UUID: %s\n", uuid_str);
	printf("TYPE: %s\n", type_str);
	printf("LABEL: %s\n", label_str);

	/* XXX: We currently support only major == 179 (mmc). */
	if (major(dev) == 179 &&
			type_str && uuid_str &&
			strcmp(type_str, "vfat")) {
		if (label_str)
			snprintf(mountpoint, PATH_MAX, "%s/%s", VOLMGR_MOUNT_PATH, label_str);
		else
			snprintf(mountpoint, PATH_MAX, "%s/%s", VOLMGR_MOUNT_PATH, uuid_str);

		printf("MOUNTPOINT: %s\n", mountpoint);
		puts("");

		ret = rmdir(mountpoint);
		if (ret < 0 && errno != ENOENT) {
			fprintf(stderr, "%s: rmdir() failed. errno: %s\n",
				dev_path, strerror(errno));
		}
		ret = mkdir(mountpoint, VOLMGR_MOUNTPOINT_MODE);
		if (!ret) {
			ret = mount(dev_path, mountpoint, type_str, 0, "");
			if (ret) {
				fprintf(stderr, "%s: mount() failed. errno: %s\n",
					dev_path, strerror(errno));
			}
		}
	} else
		puts("");

	if (uuid_str)
		free(uuid_str);
	if (type_str)
		free(type_str);
	if (label_str)
		free(label_str);
}

static void volmgr_mknod_work_cleanup(uv_work_t *wi, int status)
{
	(void)status;
	free(wi);
}

static char *volmgr_buf;

static void volmgr_poll_cb(
		uv_poll_t* handle,
		int status,
		int events)
{
	int fd;
	int nread;
	const char *action_str, *major_str, *minor_str;
	struct volmgr_token *vtok, *n, *ptr;
	action_str = major_str = minor_str = NULL;

	assert(!uv_fileno((uv_handle_t *)handle, &fd));
	nread = recv(fd, volmgr_buf, VOLMGR_RCVBUF, 0);
	assert(nread);
	if (nread < 0) {
		if (errno != EAGAIN) {
			fprintf(stderr, "Opps, failed to receive uevents. errno: %s\n",
				strerror(errno));
			uv_stop(handle->loop);
		}

		return;
	}
	vtok = volmgr_token_build(volmgr_buf, nread);
	for_each_volmgr_token(ptr, n, vtok) {
		if (!strcmp(ptr->key, "ACTION"))
			action_str = ptr->value;
		if (!strcmp(ptr->key, "MAJOR"))
			major_str = ptr->value;
		if (!strcmp(ptr->key, "MINOR"))
			minor_str = ptr->value;
	}
	if (action_str && major_str && minor_str
		&& !strcmp(action_str, "add")) {

		unsigned int major = atoi(major_str);
		unsigned int minor = atoi(minor_str);
		dev_t dev = makedev(major, minor);
		uv_work_t *wi = malloc(sizeof(uv_work_t));
		if (wi) {
			wi->data = (void *)(uintptr_t)dev;
			uv_queue_work(
				handle->loop,
				wi,
				volmgr_mknod_work,
				volmgr_mknod_work_cleanup);
		}
	}

	volmgr_token_destroy(vtok);
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
	int ret;
	umask(0);
	ret = mkdir(
		VOLMGR_DEV_PATH,
		VOLMGR_DEV_PATH_MODE);
	if (ret < 0 && errno != EEXIST) {
		fprintf(stderr, "Failed to make directory %s. errno: %s\n",
			VOLMGR_DEV_PATH, strerror(errno));
		return EXIT_FAILURE;
	}
	ret = mkdir(VOLMGR_MOUNT_PATH, VOLMGR_MOUNT_PATH_MODE);
	if (ret < 0 && errno != EEXIST) {
		fprintf(stderr, "Failed to make directory %s. errno: %s\n",
			VOLMGR_MOUNT_PATH, strerror(errno));
		return EXIT_FAILURE;
	}

	volmgr_buf = mmap(
			NULL,
			VOLMGR_RCVBUF,
			PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANON,
			-1,
			0);
	assert(volmgr_buf);
	volmgr_loop();
	munmap(volmgr_buf, VOLMGR_RCVBUF);
	return EXIT_SUCCESS;
}
