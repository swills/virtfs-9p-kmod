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

#ifndef VIRTIO_FS_9P_H
#define VIRTIO_FS_9P_H

#include <sys/types.h>

enum p9_cmds_t {
	P9PROTO_TLERROR = 6,
	P9PROTO_RLERROR,
	P9PROTO_TSTATFS = 8,
	P9PROTO_RSTATFS,
	P9PROTO_TLOPEN = 12,
	P9PROTO_RLOPEN,
	P9PROTO_TLCREATE = 14,
	P9PROTO_RLCREATE,
	P9PROTO_TSYMLINK = 16,
	P9PROTO_RSYMLINK,
	P9PROTO_TMKNOD = 18,
	P9PROTO_RMKNOD,
	P9PROTO_TRENAME = 20,
	P9PROTO_RRENAME,
	P9PROTO_TREADLINK = 22,
	P9PROTO_RREADLINK,
	P9PROTO_TGETATTR = 24,
	P9PROTO_RGETATTR,
	P9PROTO_TSETATTR = 26,
	P9PROTO_RSETATTR,
	P9PROTO_TXATTRWALK = 30,
	P9PROTO_RXATTRWALK,
	P9PROTO_TXATTRCREATE = 32,
	P9PROTO_RXATTRCREATE,
	P9PROTO_TREADDIR = 40,
	P9PROTO_RREADDIR,
	P9PROTO_TFSYNC = 50,
	P9PROTO_RFSYNC,
	P9PROTO_TLOCK = 52,
	P9PROTO_RLOCK,
	P9PROTO_TGETLOCK = 54,
	P9PROTO_RGETLOCK,
	P9PROTO_TLINK = 70,
	P9PROTO_RLINK,
	P9PROTO_TMKDIR = 72,
	P9PROTO_RMKDIR,
	P9PROTO_TRENAMEAT = 74,
	P9PROTO_RRENAMEAT,
	P9PROTO_TUNLINKAT = 76,
	P9PROTO_RUNLINKAT,
	P9PROTO_TVERSION = 100,
	P9PROTO_RVERSION,
	P9PROTO_TAUTH = 102,
	P9PROTO_RAUTH,
	P9PROTO_TATTACH = 104,
	P9PROTO_RATTACH,
	P9PROTO_TERROR = 106,
	P9PROTO_RERROR,
	P9PROTO_TFLUSH = 108,
	P9PROTO_RFLUSH,
	P9PROTO_TWALK = 110,
	P9PROTO_RWALK,
	P9PROTO_TOPEN = 112,
	P9PROTO_ROPEN,
	P9PROTO_TCREATE = 114,
	P9PROTO_RCREATE,
	P9PROTO_TREAD = 116,
	P9PROTO_RREAD,
	P9PROTO_TWRITE = 118,
	P9PROTO_RWRITE,
	P9PROTO_TCLUNK = 120,
	P9PROTO_RCLUNK,
	P9PROTO_TREMOVE = 122,
	P9PROTO_RREMOVE,
	P9PROTO_TSTAT = 124,
	P9PROTO_RSTAT,
	P9PROTO_TWSTAT = 126,
	P9PROTO_RWSTAT,
};

/* File Open Modes */
enum p9_open_mode_t {
	P9PROTO_OREAD = 0x00,
	P9PROTO_OWRITE = 0x01,
	P9PROTO_ORDWR = 0x02,
	P9PROTO_OEXEC = 0x03,
	P9PROTO_OTRUNC = 0x10,
	P9PROTO_OREXEC = 0x20,
	P9PROTO_ORCLOSE = 0x40,
	P9PROTO_OAPPEND = 0x80,
	P9PROTO_OEXCL = 0x1000,
};

/* FIle Permissions */
enum p9_perm_t {
	P9PROTO_DMDIR = 0x80000000,
	P9PROTO_DMAPPEND = 0x40000000,
	P9PROTO_DMEXCL = 0x20000000,
	P9PROTO_DMMOUNT = 0x10000000,
	P9PROTO_DMAUTH = 0x08000000,
	P9PROTO_DMTMP = 0x04000000,
	P9PROTO_DMSYMLINK = 0x02000000,
	P9PROTO_DMLINK = 0x01000000,
	P9PROTO_DMDEVICE = 0x00800000,
	P9PROTO_DMNAMEDPIPE = 0x00200000,
	P9PROTO_DMSOCKET = 0x00100000,
	P9PROTO_DMSETUID = 0x00080000,
	P9PROTO_DMSETGID = 0x00040000,
	P9PROTO_DMSETVTX = 0x00010000,
};

enum p9_qid_t {
	P9PROTO_QTDIR = 0x80,
	P9PROTO_QTAPPEND = 0x40,
	P9PROTO_QTEXCL = 0x20,
	P9PROTO_QTMOUNT = 0x10,
	P9PROTO_QTAUTH = 0x08,
	P9PROTO_QTTMP = 0x04,
	P9PROTO_QTSYMLINK = 0x02,
	P9PROTO_QTLINK = 0x01,
	P9PROTO_QTFILE = 0x00,
};

/* P9 Magic Numbers */
#define P9PROTO_NOFID	(uint32_t)(~0)

/* Exchange unit between Qemu and Client */
struct p9_qid {
	uint8_t type;
	uint32_t version;
	uint64_t path;
};

/* FS information stat structure */
struct p9_statfs {
	uint32_t type;
	uint32_t bsize;
	uint64_t blocks;
	uint64_t bfree;
	uint64_t bavail;
	uint64_t files;
	uint64_t ffree;
	uint64_t fsid;
	uint32_t namelen;
};


/* This should be in sync with 9p's V9fsStat */
struct p9_wstat {
	uint16_t size;
	uint16_t type;
	uint32_t dev;
	struct p9_qid qid;
	uint32_t mode;
	uint32_t atime;
	uint32_t mtime;
	uint64_t length;
	char *name;
	char *uid;
	char *gid;
	char *muid;
	char *extension;	/* 9p2000.u extensions */
	uid_t n_uid;		/* 9p2000.u extensions */
	gid_t n_gid;		/* 9p2000.u extensions */
	uid_t n_muid;		/* 9p2000.u extensions */
};

/* The linux version */
struct p9_stat_dotl {
	uint64_t st_result_mask;
	struct p9_qid qid;
	uint32_t st_mode;
	uid_t st_uid;
	gid_t st_gid;
	uint64_t st_nlink;
	uint64_t st_rdev;
	uint64_t st_size;
	uint64_t st_blksize;
	uint64_t st_blocks;
	uint64_t st_atime_sec;
	uint64_t st_atime_nsec;
	uint64_t st_mtime_sec;
	uint64_t st_mtime_nsec;
	uint64_t st_ctime_sec;
	uint64_t st_ctime_nsec;
	uint64_t st_btime_sec;
	uint64_t st_btime_nsec;
	uint64_t st_gen;
	uint64_t st_data_version;
};

#define P9PROTO_STATS_MODE		0x00000001ULL
#define P9PROTO_STATS_NLINK		0x00000002ULL
#define P9PROTO_STATS_UID		0x00000004ULL
#define P9PROTO_STATS_GID		0x00000008ULL
#define P9PROTO_STATS_RDEV		0x00000010ULL
#define P9PROTO_STATS_ATIME		0x00000020ULL
#define P9PROTO_STATS_MTIME		0x00000040ULL
#define P9PROTO_STATS_CTIME		0x00000080ULL
#define P9PROTO_STATS_INO		0x00000100ULL
#define P9PROTO_STATS_SIZE		0x00000200ULL
#define P9PROTO_STATS_BLOCKS		0x00000400ULL

#define P9PROTO_STATS_BTIME		0x00000800ULL
#define P9PROTO_STATS_GEN		0x00001000ULL
#define P9PROTO_STATS_DATA_VERSION	0x00002000ULL

#define P9PROTO_STATS_BASIC		0x000007ffULL /* Mask for fields up to BLOCKS */
#define P9PROTO_STATS_ALL		0x00003fffULL /* Mask for All fields above */

/* PDU buffer used for SG lists. */
struct p9_buffer {
	uint32_t size;
	uint16_t tag;
	uint8_t id;
	size_t offset;
	size_t capacity;
	uint8_t *sdata;
};

#endif /* VIRTIO_FS_9P_H */
