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
 * This file consists of all the VFS interactions.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/mount.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/protosw.h>
#include <sys/sockopt.h>
#include <sys/socketvar.h>
#include <sys/pcpu.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/fnv_hash.h>
#include <sys/fcntl.h>
#include <sys/priv.h>
#include <sys/namei.h>
#include "virtfs_proto.h"
#include <dev/virtio/virtio_fs_client.h>
#include <dev/virtio/virtio_fs_9p.h>
#include "virtfs.h"

/* This count is static now. Can be made tunable later.*/
#define VIRTFS_FLUSH_RETRIES 10

static MALLOC_DEFINE(M_P9MNT, "virtfs_mount", "Mount structures for virtfs");
static uma_zone_t virtfs_node_zone;
uma_zone_t virtfs_stat_zone;
uma_zone_t virtfs_io_buffer_zone;
extern struct vop_vector virtfs_vnops;

u_quad_t
virtfs_round_filesize_to_bytes(uint64_t filesize, uint64_t bsize)
{

        if (filesize == 0 && bsize == 0)
                return 0;
        return (((filesize + bsize - 1) / bsize) * bsize);
}

u_quad_t
virtfs_pow2_filesize_to_bytes(uint64_t filesize, uint64_t bsize)
{

        if (filesize == 0 || bsize == 0)
                return 0;
        return ((filesize + bsize - 1) & ~(bsize - 1));
}

/* Dispose virtfs_node, freeing it to the uma zone.*/
void
virtfs_dispose_node(struct virtfs_node **nodep)
{
	struct virtfs_node *node;
	struct vnode *vp;

	node = *nodep;

	if (node == NULL)
		return;

	p9_debug(VOPS, "dispose_node: %p\n", *nodep);

	vp = VIRTFS_NTOV(node);
	vp->v_data = NULL;

	/* Free our associated memory */
	if (!(vp->v_vflag & VV_ROOT))
		uma_zfree(virtfs_node_zone, node);

	*nodep = NULL;
}

static int
virtfs_init(struct vfsconf *vfsp)
{

	virtfs_node_zone = uma_zcreate("virtfs node zone",
	    sizeof(struct virtfs_node), NULL, NULL, NULL, NULL, 0, 0);

	/* Create the stats zone */
	virtfs_stat_zone = uma_zcreate("virtfs stats zone",
	    sizeof(struct p9_wstat), NULL, NULL, NULL, NULL, 0, 0);

	/*
	 * Create the io_buffer zone pool to keep things simpler in case of
	 * multiple threads. Each thread works with its own so there is no
	 * contention.
	 */
	virtfs_io_buffer_zone = uma_zcreate("virtfs io_buffer zone",
	    VIRTFS_MTU, NULL, NULL, NULL, NULL, 0, 0);

	return (0);
}

static int
virtfs_uninit(struct vfsconf *vfsp)
{

	uma_zdestroy(virtfs_stat_zone);
	uma_zdestroy(virtfs_node_zone);
	uma_zdestroy(virtfs_io_buffer_zone);

	return (0);
}

static int
virtfs_unmount(struct mount *mp, int mntflags)
{
	struct virtfs_mount *vmp = VFSTOP9(mp);
	int error = 0, flags = 0, i;

	if (vmp == NULL)
		return (0);

	if (mntflags & MNT_FORCE)
		flags |= FORCECLOSE;

	virtfs_prepare_to_close(mp);

	for (i = 0; i < VIRTFS_FLUSH_RETRIES; i++) {

		/* Flush everything on this mount point.*/
		error = vflush(mp, 0, flags, curthread);

		if (error == 0 || (mntflags & MNT_FORCE) == 0)
			break;
		/* Sleep until interrupted or 1 tick expires. */
		error = tsleep(&error, PSOCK, "p9unmnt", 1);
		if (error == EINTR)
			break;
		error = EBUSY;
	}

	if (error != 0)
		goto out;

	virtfs_close_session(mp);
	/* Cleanup the mount structure. */
	free(vmp, M_P9MNT);
	mp->mnt_data = NULL;
out:
	return (error);
}

/*
 * vget_common created vnode, virtfs_node with the flags, fid (usually since this is called
 * after a client_walk, we already have a new fid for which we create the vnode and virtfs_node).
 */
int
virtfs_vget_common(struct mount *mp, struct virtfs_node *virtfs_node,
    int flags, struct p9_fid *fid, struct vnode **vpp)
{
	struct virtfs_mount *vmp;
	struct virtfs_session *p9s;
	struct vnode *vp;
	struct thread *td;
	uint32_t ino;
	int error;
	struct virtfs_inode *inode;

	td = curthread;
	vmp = VFSTOP9(mp);
	p9s = &vmp->virtfs_session;

	/* This should either be a root or the walk (which should have cloned)*/
	ino = fid->fid;

	error = vfs_hash_get(mp, ino, flags, td, vpp, NULL, NULL);
	if (error != 0 || *vpp != NULL)
		return (error);

	/*
	 * We must promote to an exclusive lock for vnode creation.  This
	 * can happen if lookup is passed LOCKSHARED.
	 */
	if ((flags & LK_TYPE_MASK) == LK_SHARED) {
		flags &= ~LK_TYPE_MASK;
		flags |= LK_EXCLUSIVE;
	}

	/* Allocate a new vnode. */
	if ((error = getnewvnode("virtfs", mp, &virtfs_vnops, &vp)) != 0) {
		*vpp = NULLVP;
		p9_debug(ERROR, "Couldnt allocate vnode from VFS \n");
		return (error);
	}
	/* If we dont have it, create one. */
	if (virtfs_node == NULL) {
		virtfs_node =  uma_zalloc(virtfs_node_zone, M_WAITOK | M_ZERO);
		virtfs_node->vfid = fid;  /* Nodes fid*/
		virtfs_node->virtfs_ses = p9s; /* Map the current session */
	} else {
		vp->v_type = VDIR; /* root vp is a directory */
		vp->v_vflag |= VV_ROOT;
	}

	vp->v_data = virtfs_node;
	virtfs_node->v_node = vp;
	inode = &virtfs_node->inode;
	inode->n_ino = fid->fid;
	VIRTFS_SET_LINKS(inode);

	VIRTFS_LOCK(p9s);
	/* Add the virtfs_node to the list for cleanup later.*/
	STAILQ_INSERT_TAIL(&p9s->virt_node_list, virtfs_node, virtfs_node_next);
	VIRTFS_UNLOCK(p9s);

	lockmgr(vp->v_vnlock, LK_EXCLUSIVE, NULL);
	error = insmntque(vp, mp);
	if (error != 0) {
		goto out;
	}
	error = vfs_hash_insert(vp, ino, flags, td, vpp, NULL, NULL);

	if (error != 0 || *vpp != NULL)
		goto out;

	/* Init the vnode with the disk info*/
	error = virtfs_reload_stats(vp);
	if (error != 0)
		goto out;

	*vpp = vp;

	return (0);
out:
	/* Something went wrong, dispose the node */
	virtfs_dispose_node(&virtfs_node);
	*vpp = NULLVP;

	return (error);
}

/* Main mount function for 9pfs*/
static int
p9_mount(struct mount *mp)
{
	struct p9_fid *fid;
	struct virtfs_mount *vmp = NULL;
	struct virtfs_session *p9s;
	struct virtfs_node *virtfs_root;
	int error = 0;

	/* Allocate and initialize the private mount structure. */
	vmp = malloc(sizeof (struct virtfs_mount), M_P9MNT, M_WAITOK | M_ZERO);
	mp->mnt_data = vmp;
	vmp->virtfs_mountp = mp;
        vmp->virtfs_filesize2bytes = virtfs_round_filesize_to_bytes;
	p9s = &vmp->virtfs_session;
	p9s->virtfs_mount = mp;
	virtfs_root = &p9s->rnp;
	/* Hardware iosize from the Qemu */
	mp->mnt_iosize_max = PAGE_SIZE;
	/*
	 * Init the session for the virtfs root. This creates a new root fid and
	 * attaches the client and server.
	 */
	fid = virtfs_init_session(mp, &error);
	if (fid == NULL) {
		goto out;
	}
	virtfs_root->vfid = fid;
	virtfs_root->virtfs_ses = p9s;
	mp->mnt_stat.f_fsid.val[1] = mp->mnt_vfc->vfc_typenum;
	mp->mnt_maxsymlinklen = 0;
	MNT_ILOCK(mp);
	mp->mnt_flag |= MNT_LOCAL;
	mp->mnt_kern_flag |= MNTK_LOOKUP_SHARED | MNTK_EXTENDED_SHARED;
	MNT_IUNLOCK(mp);
	p9_debug(VFS, "Mount successful\n");
	/* Mount structures created. */

	return (0);
out:
	p9_debug(ERROR, " Mount Failed \n");
	if (vmp != NULL) {
		free(vmp, M_P9MNT);
		mp->mnt_data = NULL;
	}
	return (error);
}

/*
 * Mount entry point.
 */
static int
virtfs_mount(struct mount *mp)
{
	int error = 0;

	/* No support for UPDATE for now */
	if (mp->mnt_flag & MNT_UPDATE)
		return (EOPNOTSUPP);

	error = p9_mount(mp);
	if (error != 0)
		(void) virtfs_unmount(mp, MNT_FORCE);

	return (error);
}

/* Create virtfs_root first. This will be called after the intial mount completes.*/
static int
virtfs_root(struct mount *mp, int lkflags, struct vnode **vpp)
{
	struct virtfs_mount *vmp = VFSTOP9(mp);
	struct virtfs_node *np = &vmp->virtfs_session.rnp;
	int error;

	if ((error = virtfs_vget_common(mp, np, lkflags, np->vfid, vpp))) {
		*vpp = NULLVP;
		return (error);
	}
	np->v_node = *vpp;
	vref(*vpp);

	return (error);
}

/* Statfs to set the base iosize for transfer from qemu*/
static int
virtfs_statfs(struct mount *mp __unused, struct statfs *buf)
{
	struct virtfs_mount *vmp = VFSTOP9(mp);
	struct virtfs_node *np = &vmp->virtfs_session.rnp;
	struct p9_statfs statfs;
	int res;

	if (np->vfid == NULL) {
		return EFAULT;
	}

	res = p9_client_statfs(np->vfid, &statfs);

	if (res == 0) {
		buf->f_type = statfs.type;
		/*
		 * We have a limit of 4k irrespective of what the
		 * Qemu server can do.
		 */
		if (statfs.bsize > PAGE_SIZE)
			buf->f_bsize = PAGE_SIZE;
		else
			buf->f_bsize = statfs.bsize;

		buf->f_iosize = buf->f_bsize;
		buf->f_blocks = statfs.blocks;
		buf->f_bfree = statfs.bfree;
		buf->f_bavail = statfs.bavail;
		buf->f_files = statfs.files;
		buf->f_ffree = statfs.ffree;
	}
	else {
		/* Atleast set these if stat fail */
		buf->f_bsize = PAGE_SIZE;
		buf->f_iosize = buf->f_bsize;   /* XXX */
	}
        if ((buf->f_bsize & (buf->f_bsize -1)) == 0)
                vmp->virtfs_filesize2bytes = virtfs_pow2_filesize_to_bytes;

	return (0);
}

static int
virtfs_fhtovp(struct mount *mp, struct fid *fhp, int flags, struct vnode **vpp)
{

	return (EINVAL);
}

struct vfsops virtfs_vfsops = {
	.vfs_init  =	virtfs_init,
	.vfs_uninit =	virtfs_uninit,
	.vfs_mount =	virtfs_mount,
	.vfs_unmount =	virtfs_unmount,
	.vfs_root =	virtfs_root,
	.vfs_statfs =	virtfs_statfs,
	.vfs_fhtovp =	virtfs_fhtovp,
};
VFS_SET(virtfs_vfsops, virtfs, VFCF_JAIL);
MODULE_VERSION(vtfs, 1);
MODULE_DEPEND(vtfs, virtio, 1, 1, 1);
MODULE_DEPEND(vtfs, vt9p, 1, 1, 1);
