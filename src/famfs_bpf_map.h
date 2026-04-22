// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (C) 2026 Micron Technology, Inc.  All rights reserved.
 *
 * Simple BPF map helpers for famfs FUSE daemon.
 * Uses raw bpf() syscall to avoid libbpf link dependency.
 */

#ifndef FAMFS_BPF_MAP_H
#define FAMFS_BPF_MAP_H

#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>
#include <linux/bpf.h>

static inline int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr,
			  unsigned int size)
{
	return (int)syscall(__NR_bpf, cmd, attr, size);
}

static inline int bpf_map_update(int fd, const void *key,
				 const void *value, uint64_t flags)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = fd;
	attr.key = (uint64_t)(unsigned long)key;
	attr.value = (uint64_t)(unsigned long)value;
	attr.flags = flags;

	return sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

static inline int bpf_map_delete(int fd, const void *key)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = fd;
	attr.key = (uint64_t)(unsigned long)key;

	return sys_bpf(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}

static inline int bpf_obj_get(const char *pathname)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.pathname = (uint64_t)(unsigned long)pathname;

	return sys_bpf(BPF_OBJ_GET, &attr, sizeof(attr));
}

#endif /* FAMFS_BPF_MAP_H */
