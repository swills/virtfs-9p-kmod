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

/*
 * This file consists of all the VFS interactions of VFS ops which include
 * mount, unmount, initilaize etc. for VirtFS.
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

/* This count is static now. Can be made tunable later */
#define VIRTFS_FLUSH_RETRIES 10

static MALLOC_DEFINE(M_P9MNT, "virtfs_mount", "Mount structures for VirtFS");
static uma_zone_t virtfs_node_zone;
uma_zone_t virtfs_io_buffer_zone;
uma_zone_t virtfs_getattr_zone;
uma_zone_t virtfs_setattr_zone;
extern struct vop_vector virtfs_vnops;

/* option parsing */
static const char *virtfs_opts[] = {
        "from", "trans", "access", NULL
};

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

/* Dispose VirtFS node, freeing it to the UMA zone */
void
virtfs_dispose_node(struct virtfs_node **npp)
{
	struct virtfs_node *node;
	struct vnode *vp;

	node = *npp;

	if (node == NULL)
		return;

	p9_debug(VOPS, "dispose_node: %p\n", *npp);

	vp = VIRTFS_NTOV(node);
	vp->v_data = NULL;

	/* Free our associated memory */
	if (!(vp->v_vflag & VV_ROOT)) {
		free(node->inode.i_name, M_TEMP);
		uma_zfree(virtfs_node_zone, node);
	}

	*npp = NULL;
}

/* Initialize memory allocation */
static int
virtfs_init(struct vfsconf *vfsp)
{

	virtfs_node_zone = uma_zcreate("VirtFS node zone",
	    sizeof(struct virtfs_node), NULL, NULL, NULL, NULL, 0, 0);

	/* Create the getattr_dotl zone */
	virtfs_getattr_zone = uma_zcreate("VirtFS getattr zone",
	    sizeof(struct p9_stat_dotl), NULL, NULL, NULL, NULL, 0, 0);

	/* Create the setattr_dotl zone */
	virtfs_setattr_zone = uma_zcreate("VirtFS setattr zone",
	    sizeof(struct p9_iattr_dotl), NULL, NULL, NULL, NULL, 0, 0);

	/*
	 * Create the io_buffer zone pool to keep things simpler in case of
	 * multiple threads. Each thread works with its own so there is no
	 * contention.
	 */
	virtfs_io_buffer_zone = uma_zcreate("VirtFS io_buffer zone",
	    VIRTFS_MTU, NULL, NULL, NULL, NULL, 0, 0);

	return (0);
}

/* Destroy all the allocated memory */
static int
virtfs_uninit(struct vfsconf *vfsp)
{

	uma_zdestroy(virtfs_node_zone);
	uma_zdestroy(virtfs_io_buffer_zone);
	uma_zdestroy(virtfs_getattr_zone);
	uma_zdestroy(virtfs_setattr_zone);

	return (0);
}

/* Function to umount VirtFS */
static int
virtfs_unmount(struct mount *mp, int mntflags)
{
	struct virtfs_mount *vmp;
	struct virtfs_session *vses;
	int error, flags, i;

	error = 0;
	flags = 0;
	vmp = VFSTOP9(mp);
	if (vmp == NULL)
		return (0);

	vses = &vmp->virtfs_session;
	if (mntflags & MNT_FORCE)
		flags |= FORCECLOSE;

	virtfs_prepare_to_close(mp);
	for (i = 0; i < VIRTFS_FLUSH_RETRIES; i++) {

		/* Flush everything on this mount point.*/
		error = vflush(mp, 1, flags, curthread);

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
	return (error);
out:
	/* Restore the flag in case of error */
	vses->clnt->trans_status = VIRTFS_CONNECT;
	return (error);
}

/*
 * Compare qid stored in VirtFS node
 * Return 1 if does not match otherwise return 0
 */
int
virtfs_node_cmp(struct vnode *vp, void *arg)
{
	struct virtfs_node *np;
	struct p9_qid *qid;

	np = vp->v_data;
	qid = (struct p9_qid *)arg;

	if (np->vqid.qid_path == qid->path) {
		if (vp->v_vflag & VV_ROOT)
			return 0;
		else if (np->vqid.qid_mode == qid->type &&
			    np->vqid.qid_version == qid->version)
			return 0;
	}

	return 1;
}

/*
 * Common code used across VirtFS to return vnode for the file represented
 * by the fid.
 * Lookup for the vnode in hash_list. This lookup is based on the qid path
 * which is unique to a file. virtfs_node_cmp is called in this lookup process.
 * I. If the vnode we are looking for is found in the hash list
 *    1. Check if the vnode is a valid vnode by reloading its stats
 *       a. if the reloading of the vnode stats returns error then remove the
 *          vnode from hash list and return
 *       b. If reloading of vnode stats returns without any error then, clunk the
 *          new fid which was created for the vnode as we know that the vnode
 *          already has a fid associated with it and return the vnode.
 *          This is to avoid fid leaks
 * II. If vnode is not found in the hash list then, create new vnode, VirtFS
 *     node and return the vnode
 */
int
virtfs_vget_common(struct mount *mp, struct virtfs_node *np, int flags,
    struct virtfs_node *parent, struct p9_fid *fid, struct vnode **vpp,
    char *name)
{
	struct virtfs_mount *vmp;
	struct virtfs_session *vses;
	struct vnode *vp;
	struct virtfs_node *node;
	struct thread *td;
	uint32_t hash;
	int error;
	struct virtfs_inode *inode;

	td = curthread;
	vmp = VFSTOP9(mp);
	vses = &vmp->virtfs_session;

	/* Look for vp in the hash_list */
	hash = fnv_32_buf(&fid->qid.path, sizeof(uint64_t), FNV1_32_INIT);
	error = vfs_hash_get(mp, hash, flags, td, &vp, virtfs_node_cmp,
	    &fid->qid);
	if (error != 0)
		return (error);
	else if (vp != NULL) {
		if (vp->v_vflag & VV_ROOT) {
			if (np == NULL)
				p9_client_clunk(fid);
			*vpp = vp;
			return (0);
		}
		error = virtfs_reload_stats_dotl(vp);
		if (error != 0) {
			node = vp->v_data;
			/* Remove stale vnode from hash list */
			vfs_hash_remove(vp);
			node->flags |= VIRTFS_NODE_DELETED;

			vput(vp);
			*vpp = NULLVP;
			vp = NULL;
		} else {
			*vpp = vp;
			/* Clunk the new fid if not root */
			p9_client_clunk(fid);
			return (0);
		}
	}

	/*
	 * We must promote to an exclusive lock for vnode creation.  This
	 * can happen if lookup is passed LOCKSHARED.
	 */
	if ((flags & LK_TYPE_MASK) == LK_SHARED) {
		flags &= ~LK_TYPE_MASK;
		flags |= LK_EXCLUSIVE;
	}

	/* Allocate a new vnode. */
	if ((error = getnewvnode("VirtFS", mp, &virtfs_vnops, &vp)) != 0) {
		*vpp = NULLVP;
		p9_debug(ERROR, "Couldnt allocate vnode from VFS \n");
		return (error);
	}

	/* If we dont have it, create one. */
	if (np == NULL) {
		np =  uma_zalloc(virtfs_node_zone, M_WAITOK | M_ZERO);
		/* Initialize the VFID list */
		VIRTFS_VFID_LOCK_INIT(np);
		STAILQ_INIT(&np->vfid_list);
		virtfs_fid_add(np, fid, VFID);

		/* Initialize the VOFID list */
		VIRTFS_VOFID_LOCK_INIT(np);
		STAILQ_INIT(&np->vofid_list);

		np->parent = parent;
		np->virtfs_ses = vses; /* Map the current session */
		inode = &np->inode;
		/*Fill the name of the file in inode */
		inode->i_name = malloc(strlen(name)+1, M_TEMP, M_NOWAIT | M_ZERO);
		strlcpy(inode->i_name, name, strlen(name)+1);
	} else {
		vp->v_type = VDIR; /* root vp is a directory */
		vp->v_vflag |= VV_ROOT;
		vref(vp); /* Increment a reference on root vnode during mount */
	}

	vp->v_data = np;
	np->v_node = vp;
	inode = &np->inode;
	inode->i_qid_path = fid->qid.path;
	VIRTFS_SET_LINKS(inode);

	/*
	 * Add the VirtFS node to the list for cleanup later.
	 * Cleanup of this VirtFS node from the list of session
	 * VirtFS nodes happen in vput() :
	 * 	- In vfs_hash_insert() after inserting this node
	 *	  to the VFS hash table.
	 *	- In error handling below.
	 */
	VIRTFS_LOCK(vses);
	STAILQ_INSERT_TAIL(&vses->virt_node_list, np, virtfs_node_next);
	VIRTFS_UNLOCK(vses);
	np->flags |= VIRTFS_NODE_IN_SESSION;

	lockmgr(vp->v_vnlock, LK_EXCLUSIVE, NULL);
	error = insmntque(vp, mp);
	if (error != 0) {
		/*
		 * vput(vp) is already called from insmntque_stddtr().
		 * Just goto 'out' to dispose the node.
		 */
		goto out;
	}

	/* Init the vnode with the disk info*/
	error = virtfs_reload_stats_dotl(vp);
	if (error != 0) {
		vput(vp);
		goto out;
	}

	error = vfs_hash_insert(vp, hash, flags, td, vpp,
	    virtfs_node_cmp, &fid->qid);
	if (error != 0) {
		goto out;
	}
	if (*vpp == NULL) {
		*vpp = vp;
	}

	return (0);
out:
	if (!IS_ROOT(np)) {
		/* Destroy the FID LIST locks */
		VIRTFS_VFID_LOCK_DESTROY(np);
		VIRTFS_VOFID_LOCK_DESTROY(np);
	}

	/* Something went wrong, dispose the node */

	/*
	 * Remove the virtfs_node from the list before we cleanup.
	 * This should ideally have been removed in vput() above.
	 * We try again here, incase it is missed from vput(), as
	 * we added this vnode explicitly to virt_node_list above.
	 */
	if ((np->flags & VIRTFS_NODE_IN_SESSION) != 0) {
		VIRTFS_LOCK(vses);
		STAILQ_REMOVE(&vses->virt_node_list, np, virtfs_node, virtfs_node_next);
		VIRTFS_UNLOCK(vses);
		np->flags &= ~VIRTFS_NODE_IN_SESSION;
	}
	virtfs_dispose_node(&np);
	*vpp = NULLVP;
	return (error);
}

/* Main mount function for 9pfs */
static int
p9_mount(struct mount *mp)
{
	struct p9_fid *fid;
	struct virtfs_mount *vmp;
	struct virtfs_session *vses;
	struct virtfs_node *virtfs_root;
	int error;
	char *from;
	int len;

	/* Verify the validity of mount options */
	if (vfs_filteropt(mp->mnt_optnew, virtfs_opts))
		return EINVAL;

	/* Extract NULL terminated mount tag from mount options */
	error = vfs_getopt(mp->mnt_optnew, "from", (void **)&from, &len);
	if (error != 0 || from[len - 1] != '\0')
		return EINVAL;

	/* Allocate and initialize the private mount structure. */
	vmp = malloc(sizeof (struct virtfs_mount), M_P9MNT, M_WAITOK | M_ZERO);
	mp->mnt_data = vmp;
	vmp->virtfs_mountp = mp;
        vmp->virtfs_filesize2bytes = virtfs_round_filesize_to_bytes;
	vmp->mount_tag = from;
	vmp->mount_tag_len = len;
	vses = &vmp->virtfs_session;
	vses->virtfs_mount = mp;
	virtfs_root = &vses->rnp;
	/* Hardware iosize from the Qemu */
	mp->mnt_iosize_max = PAGE_SIZE;
	/*
	 * Init the session for the VirtFS root. This creates a new root fid and
	 * attaches the client and server.
	 */
	fid = virtfs_init_session(mp, &error);
	if (fid == NULL) {
		goto out;
	}

	VIRTFS_VFID_LOCK_INIT(virtfs_root);
	STAILQ_INIT(&virtfs_root->vfid_list);
	virtfs_fid_add(virtfs_root, fid, VFID);
	VIRTFS_VOFID_LOCK_INIT(virtfs_root);
	STAILQ_INIT(&virtfs_root->vofid_list);
	virtfs_root->parent = virtfs_root;
	virtfs_root->flags |= VIRTFS_ROOT;
	virtfs_root->virtfs_ses = vses;
	vfs_getnewfsid(mp);
	strlcpy(mp->mnt_stat.f_mntfromname, from,
	    sizeof(mp->mnt_stat.f_mntfromname));
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

/* Mount entry point */
static int
virtfs_mount(struct mount *mp)
{
	int error;

	/* No support for UPDATE for now */
	if (mp->mnt_flag & MNT_UPDATE)
		return (EOPNOTSUPP);

	error = p9_mount(mp);
	if (error != 0)
		(void) virtfs_unmount(mp, MNT_FORCE);

	return (error);
}

/*
 * Retrieve the root vnode of this mount. After filesystem is mounted, the root
 * vnode is created for the first time. Subsequent calls to VirtFS root will
 * return the same vnode created during mount.
 */
static int
virtfs_root(struct mount *mp, int lkflags, struct vnode **vpp)
{
	struct virtfs_mount *vmp;
	struct virtfs_node *np;
	struct p9_client *clnt;
	struct p9_fid *vfid;
	int error;

	vmp = VFSTOP9(mp);
	np = &vmp->virtfs_session.rnp;
	clnt = vmp->virtfs_session.clnt;
	error = 0;

	p9_debug(VOPS, "%s: node=%p name=%s\n",__func__, np, np->inode.i_name);

	vfid = virtfs_get_fid(clnt, np, VFID, &error);

	if (error != 0) {
		/* for root use the nobody user's fid as vfid.
		 * This is used while unmounting as root when non-root
		 * user has mounted VirtFS
		 */
		if (vfid == NULL && clnt->trans_status == VIRTFS_BEGIN_DISCONNECT)
			vfid = vmp->virtfs_session.mnt_fid;
		else {
			*vpp = NULLVP;
			return error;
		}
	}

	error = virtfs_vget_common(mp, np, lkflags, np, vfid, vpp, NULL);
	if (error != 0) {
		*vpp = NULLVP;
		return (error);
	}
	np->v_node = *vpp;
	return (error);
}

/* Retrieve the file system statistics */
static int
virtfs_statfs(struct mount *mp __unused, struct statfs *buf)
{
	struct virtfs_mount *vmp;
	struct virtfs_node *np;
	struct p9_client *clnt;
	struct p9_fid *vfid;
	struct p9_statfs statfs;
	int res, error;

	vmp = VFSTOP9(mp);
	np = &vmp->virtfs_session.rnp;
	clnt = vmp->virtfs_session.clnt;
	error = 0;

	vfid = virtfs_get_fid(clnt, np, VFID, &error);
	if (error != 0) {
		return error;
	}

	res = p9_client_statfs(vfid, &statfs);

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
