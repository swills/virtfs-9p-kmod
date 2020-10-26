/*-
 * Copyright (c) 2017 Juniper Networks, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *	notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *	notice, this list of conditions and the following disclaimer in the
 *	documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef VIRTIO_FS_CLIENT_H
#define VIRTIO_FS_CLIENT_H

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/condvar.h>
#include <sys/queue.h>
#include <sys/systm.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/dirent.h>
#include <machine/stdarg.h>

#include "virtio_fs_9p.h"

enum p9_proto_versions {
	p9_proto_legacy,
	p9_proto_2000u,
	p9_proto_2000L,
};

/* P9 Request exchanged between Host and Guest */
struct p9_req_t {
	struct p9_buffer *tc;
	struct p9_buffer *rc;
};

enum transport_status {

	VIRTFS_CONNECT,
	VIRTFS_BEGIN_DISCONNECT,
	VIRTFS_DISCONNECT,
};

/* This is set by QEMU so we will oblige */
#define VIRTFS_MTU 8192

/*
 * Even though we have a 8k buffer, Qemu is typically doing 8168
 * because of a HDR of 24. Use that amount for transfers so that we dont
 * drop anything.
 */
#define VIRTFS_IOUNIT (VIRTFS_MTU - 24)
#define VIRTFS_DIRENT_LEN 256
#define P9_NOTAG 0

struct p9_client {
	struct mtx p9clnt_mtx;
	struct mtx p9req_mtx;
	struct cv req_cv;
	unsigned int msize;
	unsigned char proto_version;
	struct p9_trans_module *trans_mod;
	void *trans;
	struct unrhdr *fidpool;
	struct unrhdr *tagpool;
	enum transport_status trans_status;
};

/* The main fid structure which keeps track of the file.*/
struct p9_fid {
	struct p9_client *clnt;
	uint32_t fid;
	int mode;
	struct p9_qid qid;
	uint32_t mtu;
	uid_t uid;
};

struct p9_dirent {
	struct p9_qid qid;
	uint64_t d_off;
	unsigned char d_type;
	char d_name[VIRTFS_DIRENT_LEN];
	int len;
};

/* Session and client Init Ops */
struct p9_client *p9_client_create(struct mount *mp, int *error);
void p9_client_destroy(struct p9_client *clnt);
struct p9_fid *p9_client_attach(struct p9_client *clnt, int *error);

/* FILE OPS - These are individually called from the specific vop function */

int p9_client_open(struct p9_fid *fid, int mode);
int p9_client_close(struct p9_fid *fid);
struct p9_fid *p9_client_walk(struct p9_fid *oldfid, char *wname,
    size_t wnamelen, int clone, int *error);
struct p9_fid *p9_fid_create(struct p9_client *clnt);
void p9_fid_destroy(struct p9_fid *fid);
uint16_t p9_tag_create(struct p9_client *clnt);
void p9_tag_destroy(struct p9_client *clnt, uint16_t tag);
int p9_client_clunk(struct p9_fid *fid);
int p9_client_version(struct p9_client *clnt);
int p9_client_readdir(struct p9_fid *fid, char *data, uint64_t offset, uint32_t count);
int p9_client_read(struct p9_fid *fid, uint64_t offset, uint32_t count, char *data);
int p9_client_write(struct p9_fid *fid, uint64_t offset, uint32_t count, char *data);
int p9_client_file_create(struct p9_fid *fid, char *name, uint32_t perm, int mode,
    char *extension);
int p9_client_remove(struct p9_fid *fid);
int p9_dirent_read(struct p9_client *clnt, char *buf, int start, int len,
    struct p9_dirent *dirent);
int p9_client_stat(struct p9_fid *fid, struct p9_wstat **stat);
int p9_client_wstat(struct p9_fid *fid, struct p9_wstat *wst);
int p9_client_statfs(struct p9_fid *fid, struct p9_statfs *stat);
int p9_client_statread(struct p9_client *clnt, char *data, size_t len, struct p9_wstat *st);
int p9_is_proto_dotu(struct p9_client *clnt);
int p9_is_proto_dotl(struct p9_client *clnt);
void p9_client_cb(struct p9_client *c, struct p9_req_t *req);
int p9stat_read(struct p9_client *clnt, char *data, size_t len, struct p9_wstat *st);
void p9_client_disconnect(struct p9_client *clnt);
void p9_client_begin_disconnect(struct p9_client *clnt);

extern int p9_debug_level; /* All debugs on now */

#define P9_DEBUG_TRANS			0x0001
#define P9_DEBUG_SUBR			0x0002
#define P9_DEBUG_VFS			0x0004
#define P9_DEBUG_PROTO			0x0008
#define P9_DEBUG_VOPS			0x0010
#define P9_DEBUG_ERROR			0x0020
#define P9_DEBUG_VNODE			0x0040
#define P9_DEBUG_DIR			0x0080
#define P9_DEBUG_NAMECACHE		0x0100
#define P9_DEBUG_NODE			0x0200

#define p9_debug(category, fmt, ...) do {			\
	if ((p9_debug_level & P9_DEBUG_##category) != 0)	\
		printf(fmt, ##__VA_ARGS__);			\
} while (0)

#endif /* VIRTIO_FS_CLIENT_H */
