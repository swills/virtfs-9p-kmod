/*-
 * Copyright (c) 2017-2020 Juniper Networks, Inc.
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

/* This file has prototypes specific to the VirtFS file system */

#ifndef __VIRTFS__
#define __VIRTFS__

struct virtfs_session;

/*
 * The in memory representation of the on disk inode. Save the current
 * fields to write it back later.
 */
struct virtfs_inode {
        /* Make it simple first, Add more fields later */
	uint64_t i_size;	/* size of the inode */
	uint16_t i_type;	/* type of inode */
	uint32_t i_dev;		/* type of device */
	uint32_t i_mode;	/* mode of the inode */
	uint32_t i_atime;	/* time of last access */
	uint32_t i_mtime;	/* time of last modification */
	uint32_t i_ctime;	/* time of last status change */
	uint32_t i_atime_nsec;	/* times of last access in nanoseconds resolution */
	uint32_t i_mtime_nsec;	/* time of last modification in nanoseconds resolution */
	uint32_t i_ctime_nsec;	/* time of last status change in nanoseconds resolution */
	uint64_t i_length;
	char *i_name;		/* inode name */
	char *i_uid;		/* inode user id */
	char *i_gid;		/* inode group id */
	char *i_muid;
	char *i_extension;       /* 9p2000.u extensions */
	uid_t n_uid;            /* 9p2000.u extensions */
	gid_t n_gid;            /* 9p2000.u extensions */
	uid_t n_muid;           /* 9p2000.u extensions */
	/* bookkeeping info on the client. */
	uint16_t i_links_count;  /*number of references to the inode*/
	uint64_t i_qid_path;    /* using inode number for reference. */
	uint64_t i_flags;
	uint64_t blksize;	/* block size for file system */
	uint64_t blocks;	/* number of 512B blocks allocated */
	uint64_t gen;		/* reserved for future use */
	uint64_t data_version;	/* reserved for future use */

};

#define VIRTFS_VFID_MTX(_sc) (&(_sc)->vfid_mtx)
#define VIRTFS_VFID_LOCK(_sc) mtx_lock(VIRTFS_VFID_MTX(_sc))
#define VIRTFS_VFID_UNLOCK(_sc) mtx_unlock(VIRTFS_VFID_MTX(_sc))
#define VIRTFS_VFID_LOCK_INIT(_sc) mtx_init(VIRTFS_VFID_MTX(_sc), \
    "VFID List lock", NULL, MTX_DEF)
#define VIRTFS_VFID_LOCK_DESTROY(_sc) mtx_destroy(VIRTFS_VFID_MTX(_sc))

#define VIRTFS_VOFID_MTX(_sc) (&(_sc)->vofid_mtx)
#define VIRTFS_VOFID_LOCK(_sc) mtx_lock(VIRTFS_VOFID_MTX(_sc))
#define VIRTFS_VOFID_UNLOCK(_sc) mtx_unlock(VIRTFS_VOFID_MTX(_sc))
#define VIRTFS_VOFID_LOCK_INIT(_sc) mtx_init(VIRTFS_VOFID_MTX(_sc), \
    "VOFID List lock", NULL, MTX_DEF)
#define VIRTFS_VOFID_LOCK_DESTROY(_sc) mtx_destroy(VIRTFS_VOFID_MTX(_sc))

#define VFID	0x01
#define VOFID	0x02

/* A Plan9 node. */
struct virtfs_node {
	STAILQ_HEAD( ,p9_fid) vfid_list;	/* vfid related to uid */
	struct mtx vfid_mtx;			/* mutex for vfid list */
	STAILQ_HEAD( ,p9_fid) vofid_list;	/* vofid related to uid */
	struct mtx vofid_mtx;			/* mutex for vofid list */
	struct virtfs_node *parent;		/* pointer to parent VirtFS node */
	struct virtfs_qid vqid;			/* the server qid, will be from the host */
	struct vnode *v_node;			/* vnode for this fs_node. */
	struct virtfs_inode inode;		/* in memory representation of ondisk information*/
	struct virtfs_session *virtfs_ses;	/*  Session_ptr for this node */
	STAILQ_ENTRY(virtfs_node) virtfs_node_next;
	uint64_t flags;
};

#define VIRTFS_VTON(vp) ((vp)->v_data)
#define VIRTFS_NTOV(node) ((node)->v_node)
#define	VFSTOP9(mp) ((mp)->mnt_data)
#define QEMU_DIRENTRY_SZ	25
#define VIRTFS_NODE_MODIFIED	0x1  /* indicating file change */
#define VIRTFS_ROOT		0x2  /* indicating root VirtFS node */
#define VIRTFS_NODE_DELETED	0x4  /* indicating file or directory delete */
#define VIRTFS_NODE_IN_SESSION	0x8  /* virtfs_node is in the session - virt_node_list */
#define IS_ROOT(node)	(node->flags & VIRTFS_ROOT)

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
	unsigned char flags;				/* these flags for the session */
	struct mount *virtfs_mount;			/* mount point */
	struct virtfs_node rnp;				/* root VirtFS node for this session */
	uid_t uid;					/* the uid that has access */
	const char *uname;				/* user name to mount as */
	const char *aname;				/* name of remote file tree being mounted */
	struct p9_client *clnt;				/* 9p client */
	struct mtx virtfs_mtx;				/* mutex used for guarding the chain.*/
	STAILQ_HEAD( ,virtfs_node) virt_node_list;	/* list of VirtFS nodes in this session*/
	struct p9_fid *mnt_fid;				/* to save nobody 's fid for unmounting as root user */
};

typedef u_quad_t (*virtfs_filesize2bytes_t)(uint64_t filesize, uint64_t bsize);
struct virtfs_mount {
	struct virtfs_session virtfs_session;		/* per instance session information */
	struct mount *virtfs_mountp;			/* mount point */
        virtfs_filesize2bytes_t virtfs_filesize2bytes;	/* file size in bytes */
	int mount_tag_len;				/* length of the mount tag */
	char *mount_tag;				/* mount tag used */
};

/* All session flags based on 9p versions  */
enum virt_session_flags {
	VIRTFS_PROTO_2000U	= 0x01,
	VIRTFS_PROTO_2000L	= 0x02,
};

/* Session access flags */
#define P9_ACCESS_ANY		0x04	/* single attach for all users */
#define P9_ACCESS_SINGLE	0x08	/* access to only the user who mounts */
#define P9_ACCESS_USER		0x10	/* new attach established for every user */
#define P9_ACCESS_MASK	(P9_ACCESS_ANY|P9_ACCESS_SINGLE|P9_ACCESS_USER)

u_quad_t virtfs_round_filesize_to_bytes(uint64_t filesize, uint64_t bsize);
u_quad_t virtfs_pow2_filesize_to_bytes(uint64_t filesize, uint64_t bsize);

/* These are all the VIRTFS specific vops */
int virtfs_stat_vnode_l(void);
int virtfs_stat_vnode_dotl(struct p9_stat_dotl *st, struct vnode *vp);
int virtfs_reload_stats_dotl(struct vnode *vp);
int virtfs_proto_dotl(struct virtfs_session *vses);
struct p9_fid *virtfs_init_session(struct mount *mp, int *error);
void virtfs_close_session(struct mount *mp);
void virtfs_prepare_to_close(struct mount *mp);
void virtfs_complete_close(struct mount *mp);
int virtfs_vget(struct mount *mp, ino_t ino, int flags, struct vnode **vpp);
int virtfs_vget_common(struct mount *mp, struct virtfs_node *np, int flags,
    struct virtfs_node *parent, struct p9_fid *fid, struct vnode **vpp,
    char *name);
int virtfs_node_cmp(struct vnode *vp, void *arg);
void virtfs_dispose_node(struct virtfs_node **npp);
void virtfs_cleanup(struct virtfs_node *vp);
void virtfs_fid_remove_all(struct virtfs_node *np);
void virtfs_fid_remove(struct virtfs_node *np, struct p9_fid *vfid,
    int fid_type);
void virtfs_fid_add(struct virtfs_node *np, struct p9_fid *fid,
    int fid_type);
struct p9_fid *virtfs_get_fid_from_uid(struct virtfs_node *np,
    uid_t uid, int fid_type);
struct p9_fid *virtfs_get_fid(struct p9_client *clnt,
    struct virtfs_node *np, int fid_type, int *error);
#endif /* __VIRTFS__ */
