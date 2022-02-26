/*-
 * Copyright (c) 2017 Juniper Networks, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
/*
 * Plan9 filesystem (9P2000.u) protocol definitions.
 */

#ifndef	__VIRTFS_PROTO_H__
#define	__VIRTFS_PROTO_H__

#include <dev/virtio/virtio_fs_9p.h>

/* QID: Unique identification for the file being accessed */
struct virtfs_qid {
	uint8_t qid_mode;	/* file mode specifiying file type */
	uint32_t qid_version;	/* version of the file */
	uint64_t qid_path;	/* unique integer among all files in hierarchy */
};

/* File permissions */
#define	VIRTFS_OREAD	0
#define	VIRTFS_OWRITE	1
#define	VIRTFS_ORDWR	2
#define	VIRTFS_OEXEC	3
#define	VIRTFS_OTRUNC	0x10

#endif /* __VIRTFS_PROTO_H__ */
