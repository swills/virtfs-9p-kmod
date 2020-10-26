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

/* This file has prototypes specifc and used all over the FS .*/
#ifndef __VIRTFS__
#define __VIRTFS__

struct virtfs_session;

/*
 * The in memory representation of the on disk inode. Save the current
 * fields to write it back later.
 */
struct virtfs_inode {
        /* Make it simple first, Add more fields later */
	uint64_t i_size;
	uint16_t i_type;
	uint32_t i_dev;
	uint32_t i_mode;
	uint32_t i_atime;
	uint32_t i_mtime;
	uint64_t i_length;
	char *i_name;
	char *i_uid;
	char *i_gid;
	char *i_muid;
	char *i_extension;       /* 9p2000.u extensions */
	uid_t n_uid;            /* 9p2000.u extensions */
	gid_t n_gid;            /* 9p2000.u extensions */
	uid_t n_muid;           /* 9p2000.u extensions */
	/* bookkeeping info on the client. */
	uint16_t i_links_count;  /*number of references to the inode*/
	uint64_t n_ino;    /* using inode number for reference. */
	uint64_t i_flags;

};

/* A Plan9 node. */
struct virtfs_node {
	struct p9_fid *vfid; /*node fid*/
	struct p9_fid *vofid; /* open fid for this file */
	uint32_t v_opens; /* Number of open handlers. */
	struct virtfs_qid vqid; /* the server qid, will be from the host*/
	struct vnode *v_node; /* vnode for this fs_node. */
	struct virtfs_inode inode; /* In memory representation of ondisk information*/
	struct virtfs_session *virtfs_ses; /*  Session_ptr for this node */
	STAILQ_ENTRY(virtfs_node) virtfs_node_next;
	uint64_t flags;
};

#define VIRTFS_VTON(vp) ((vp)->v_data)
#define VIRTFS_NTOV(node) ((node)->v_node)
#define	VFSTOP9(mp) ((mp)->mnt_data)
#define QEMU_DIRENTRY_SZ	25
#define	MAXUNAMELEN		32
#define VIRTFS_NODE_MODIFIED	0x1  /* Indicating file change */

#define VIRTFS_SET_LINKS(inode) do {	\
	(inode)->i_links_count = 1;	\
} while (0)				\

#define VIRTFS_INCR_LINKS(inode) do {	\
	(inode)->i_links_count++;	\
} while (0)				\

#define VIRTFS_DECR_LINKS(inode) do {	\
	(inode)->i_links_count--;	\
} while (0)				\

#define VIRTFS_CLR_LINKS(inode) do {	\
	(inode)->i_links_count = 0;	\
} while (0)				\

#define VIRTFS_MTX(_sc) (&(_sc)->virtfs_mtx)
#define VIRTFS_LOCK(_sc) mtx_lock(VIRTFS_MTX(_sc))
#define VIRTFS_UNLOCK(_sc) mtx_unlock(VIRTFS_MTX(_sc))
#define VIRTFS_LOCK_INIT(_sc) mtx_init(VIRTFS_MTX(_sc), \
    "VIRTFS session chain lock", NULL, MTX_DEF)
#define VIRTFS_LOCK_DESTROY(_sc) mtx_destroy(VIRTFS_MTX(_sc))

/* Session structure for the FS */
struct virtfs_session {
	unsigned char flags; /* these flags for the session */
	struct mount *virtfs_mount; /* mount point */
	struct virtfs_node rnp; /* root virtfs_node for this session */
	uid_t uid;     /* the uid that has access */
	struct p9_client *clnt; /* 9p client */
	struct mtx virtfs_mtx; /* mutex used for guarding the chain.*/
	STAILQ_HEAD( ,virtfs_node) virt_node_list; /* All virtfs_nodes in this session*/
};

typedef u_quad_t (*virtfs_filesize2bytes_t)(uint64_t filesize, uint64_t bsize);
struct virtfs_mount {
	struct virtfs_session virtfs_session;
	struct mount *virtfs_mountp;
        virtfs_filesize2bytes_t virtfs_filesize2bytes;
};

/* All session flags based on 9p versions  */
enum virt_session_flags {
	VIRTFS_PROTO_2000U	= 0x01,
	VIRTFS_PROTO_2000L	= 0x02,
};

u_quad_t virtfs_round_filesize_to_bytes(uint64_t filesize, uint64_t bsize);
u_quad_t virtfs_pow2_filesize_to_bytes(uint64_t filesize, uint64_t bsize);

/* These are all the VIRTFS specific vops */
int virtfs_stat_vnode_l(void);
int virtfs_stat_vnode_u(struct p9_wstat *st, struct vnode *vp);
int virtfs_reload_stats(struct vnode *vp);
int virtfs_proto_dotl(struct virtfs_session *virtfss);
struct p9_fid *virtfs_init_session(struct mount *mp, int *error);
void virtfs_close_session(struct mount *mp);
void virtfs_prepare_to_close(struct mount *mp);
void virtfs_complete_close(struct mount *mp);
int virtfs_vget(struct mount *mp, ino_t ino, int flags, struct vnode **vpp);
int virtfs_vget_common(struct mount *mp, struct virtfs_node *np, int flags,
    struct p9_fid *fid, struct vnode **vpp);
void virtfs_dispose_node(struct virtfs_node **node);
int virtfs_cleanup(struct virtfs_node *vp);

#endif /* __VIRTFS__ */
