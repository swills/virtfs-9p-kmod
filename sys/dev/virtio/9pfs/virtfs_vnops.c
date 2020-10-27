/*
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/fcntl.h>
#include <sys/param.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/dirent.h>
#include <sys/namei.h>
#include <sys/stat.h>
#include <sys/priv.h>
#include <sys/types.h>
#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/vm_object.h>
#include <vm/vnode_pager.h>
#include <sys/buf.h>
#include <sys/bio.h>
#include "virtfs_proto.h"
#include "virtfs.h"
#include <dev/virtio/virtio_fs_client.h>

/* File permissions. */
#define IEXEC		0000100 /* Executable. */
#define IWRITE		0000200 /* Writeable. */
#define IREAD		0000400 /* Readable. */
#define ISVTX		0001000 /* Sticky bit. */
#define ISGID		0002000 /* Set-gid. */
#define ISUID		0004000 /* Set-uid. */

static MALLOC_DEFINE(M_P9UIOV, "uio", "UIOV structures for strategy in virtfs");
extern uma_zone_t virtfs_stat_zone;
extern uma_zone_t virtfs_io_buffer_zone;
/* For the root vnode's vnops. */
struct vop_vector virtfs_vnops;

static uint32_t virtfs_unix2p9_mode(uint32_t mode);

static void
virtfs_itimes(struct vnode *vp)
{
	struct virtfs_node *node = VIRTFS_VTON(vp);
	struct timespec ts;
	struct virtfs_inode *inode = &node->inode;

	vfs_timestamp(&ts);
	inode->i_mtime = ts.tv_sec;
}

/*
 * Cleanup the virtfs_node, the in memory representation of every
 * vnode for VIRTFS. The cleanup includes invalidating all cache entries
 * for the vnode, destroying the object, hash removal, removing it from
 * the list of session virtfs_nodes, and disposing of the virtfs_node.
 * Basically it is doing a reverse of what a create/vget does.
 */
int
virtfs_cleanup(struct virtfs_node *node)
{
	struct vnode *vp = VIRTFS_NTOV(node);
	struct virtfs_session *ses = node->virtfs_ses;

	/* Invalidate all entries to a particular vnode. */
	cache_purge(vp);
	/* Destroy the vm object and flush associated pages. */
	vnode_destroy_vobject(vp);
	vfs_hash_remove(vp);
	/* Remove the virtfs_node from the list before we cleanup.*/
	VIRTFS_LOCK(ses);
	STAILQ_REMOVE(&ses->virt_node_list, node, virtfs_node, virtfs_node_next);
	VIRTFS_UNLOCK(ses);
	/* Dispose all node knowledge.*/
	virtfs_dispose_node(&node);

	return (0);
}

/*
 * Reclaim vop is defined to be called for every vnode. This starts of
 * the cleanup by clunking(remove the fid on the server) and calls cleanup
 * to cleanup the resources allocated for virtfs_node.
 */
static int
virtfs_reclaim(struct vop_reclaim_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct virtfs_node *virtfs_node = VIRTFS_VTON(vp);

	p9_debug(VOPS, "%s: vp:%p node:%p\n", __func__, vp, virtfs_node);

	if (virtfs_node == NULL)
		return (0);

	if (virtfs_node->vfid != NULL)
		(void)p9_client_clunk(virtfs_node->vfid);

	virtfs_cleanup(virtfs_node);

	return (0);
}

/*
 * virtfs_lookup is called for every component name to be searched for.
 * Here we have implemented our own cache for the component names. Once
 * the component name is not found in the cache, we check for the name
 * by doing the actual client_walk. If the component is present in the cache
 * we still need to check with the server if the file entry still exists as
 * someone from below us can remove the file. Hence we send a getattr to check
 * this with the server, If we return an error, we return ENOENT, So that the
 * user can take appropiate action if he is on a deleted directory. If the entry
 * is legit (a success from the server) we return success.
 * If the cache doesnt have an entry, then we do the client_walk which checks
 * with the server if the file exists. We build our vnode, virtfs_node based on
 * the return values. If create flag is set, we return EJUSTRETURN for the vfs
 * to handle the create case in case the file is not found on the server.
 * In all other cases an ENOENT is returned.
 */
static int
virtfs_lookup(struct vop_lookup_args *ap)
{
	struct vnode *dvp = ap->a_dvp;
	struct vnode **vpp = ap->a_vpp, *vp;
	struct componentname *cnp = ap->a_cnp;
	struct virtfs_node *dnp = VIRTFS_VTON(dvp), *newnp; /*dir p9_node */
	struct virtfs_session *p9s = dnp->virtfs_ses;
	struct mount *mp = p9s->virtfs_mount; /* Get the mount point */
	struct p9_fid *newfid = NULL;
	int error = 0, nameiop, islastcn, ltype;
	struct vattr vattr;
	int flags = cnp->cn_flags;

	nameiop = cnp->cn_nameiop;
	islastcn = flags & ISLASTCN;
	*vpp = NULLVP;

	p9_debug(VOPS, "lookup\n");

	/* Do the cache part ourselves */
	if ((flags & ISLASTCN) && (mp->mnt_flag & MNT_RDONLY) &&
	    (cnp->cn_nameiop == DELETE))
		return (EROFS);

	if (dvp->v_type != VDIR)
		return (ENOTDIR);

	/* rename is not supported on this version */
	if (nameiop == RENAME) {
		p9_debug(VOPS, "Rename is not supported \n");
		return (ENOTSUP);
	}

	/* Look for the entry in the component cache*/
	error = cache_lookup(dvp, vpp, cnp, NULL, NULL);

	if (error > 0 && error != ENOENT) {
		p9_debug(VOPS, "Cache lookup error %d \n",error);
		return (error);
	}

	if (error == -1) {
		vp = *vpp;
		newnp = VIRTFS_VTON(vp);
		if ((error = VOP_GETATTR(vp, &vattr, cnp->cn_cred)) == 0) {
			if (cnp->cn_nameiop != LOOKUP && (flags & ISLASTCN))
				cnp->cn_flags |= SAVENAME;
			return (0);
		}
		/*
		 * This case, we have an error coming from getattr,
		 * act accordingly.
		 */
		cache_purge(vp);
		if (dvp != vp)
			vput(vp);
		else
			vrele(vp);

		*vpp = NULLVP;

	} else if (error == ENOENT) {

#if __FreeBSD_version >= 1300063
		if (dvp->v_iflag & VIRF_DOOMED)
#else
		if (dvp->v_iflag & VI_DOOMED)
#endif
			return (ENOENT);
		if (VOP_GETATTR(dvp, &vattr, cnp->cn_cred) == 0)
			return (ENOENT);
		cache_purge_negative(dvp);
	}
	/* Reset values */
	error = 0;
	vp = NULLVP;
	/*
	* If the client_walk fails, it means the file looking for doesnt exist.
	* Create the file is the flags are set or just return the error
	*/
	newfid = p9_client_walk(dnp->vfid, cnp->cn_nameptr, cnp->cn_namelen, 1, &error);

	if (error != 0 || newfid == NULL) {

		if (vp != NULLVP) {
			vput(vp);
			*vpp = NULLVP;
		}

		if (error != ENOENT)
			return (error);

		/* The requested file was not found. */
		if ((cnp->cn_nameiop == CREATE && (flags & ISLASTCN))) {

			if (mp->mnt_flag & MNT_RDONLY)
				return (EROFS);
			cnp->cn_flags |= SAVENAME;
			return (EJUSTRETURN);
		}
		return (ENOENT);
	}

	/* Looks like we have found an entry.  Now take care of all other cases. */
	if (flags & ISDOTDOT) {
		ltype = VOP_ISLOCKED(dvp);
		error = vfs_busy(mp, MBF_NOWAIT);

		if (error != 0) {
			vfs_ref(mp);
#if __FreeBSD_version >= 1300074
			VOP_UNLOCK(dvp);
#else
			VOP_UNLOCK(dvp, 0);
#endif
			error = vfs_busy(mp, 0);
			VOP_LOCK(dvp, ltype | LK_RETRY);
			vfs_rel(mp);
#if __FreeBSD_version >= 1300063
			if (error == 0 && (dvp->v_iflag & VIRF_DOOMED)) {
#else
			if (error == 0 && (dvp->v_iflag & VI_DOOMED)) {
#endif
				vfs_unbusy(mp);
				error = ENOENT;
			}
			if (error != 0)
				return (error);
		}
#if __FreeBSD_version >= 1300074
		VOP_UNLOCK(dvp);
#else
		VOP_UNLOCK(dvp, 0);
#endif

		/* Try to create/reuse the node */
		error =  virtfs_vget_common(mp, NULL, cnp->cn_lkflags, newfid, &vp);

		if (error == 0) {
			p9_debug(VOPS, "Node created OK\n");
			*vpp = vp;
		}
		vfs_unbusy(mp);
		if (vp != dvp)
			VOP_LOCK(dvp, ltype | LK_RETRY);

#if __FreeBSD_version >= 1300063
		if (dvp->v_iflag & VIRF_DOOMED) {
#else
		if (dvp->v_iflag & VI_DOOMED) {
#endif
			if (error == 0) {
				if (vp == dvp)
					vrele(vp);
				else
					vput(vp);
			}
			error = ENOENT;
		}

		if (error != 0)
			return (error);
	} else {
		/*
		 * client_walk is equivalent to searching a component name in a directory(fid)
		 * here. If new fid is returned, we have found an entry for this component name
		 * so, go and create the rest of the vnode infra(vget_common) for the returned
		 * newfid.
		 */
		error = virtfs_vget_common(mp, NULL, cnp->cn_lkflags, newfid, &vp);

		if (error != 0)
			return (error);
		*vpp = vp;
		vref(*vpp);
	}

	if (cnp->cn_nameiop != LOOKUP && (flags & ISLASTCN))
		cnp->cn_flags |= SAVENAME;

	/* Store the result the cache if MAKEENTRY is specified in flags */
	if ((cnp->cn_flags & MAKEENTRY) != 0)
		cache_enter(dvp, *vpp, cnp);

	*vpp = vp;

	return (error);
}

/*
 * Create wrapper is the common create function called by file/directory created with
 * respective flags. We first open the directory in order to create the file under the
 * parent. For this as 9p protocol suggests, we need to client_walk to create the open fid.
 * Once we have the open fid, the file_create function creates the direntry with the name
 * and perm specified under the parent dir. If this succeeds( an entry is created for the
 * new file on the server), we create our metadata for this file( vnode, virtfs_node calling
 * vget). Once we are done, we clunk the open fid of the directory.
 */
static int
create_common(struct virtfs_node *dir_node,
    struct componentname *cnp, char *extension, uint32_t perm, uint8_t mode,
    struct vnode **vpp)
{
	char *name = cnp->cn_nameptr;
	struct p9_fid *ofid, *newfid;
	struct virtfs_session *ses = dir_node->virtfs_ses;
	struct mount *mp = ses->virtfs_mount;
	int err;

	p9_debug(VOPS, "name %pd\n", name);
	err = 0;
	ofid = NULL;
	newfid = NULL;
	/*
	 * Same way as open, we have to walk to create a clone and
	 * use to open the directory.
	 */

	if (dir_node->vofid == NULL) {
		dir_node->vofid = p9_client_walk(dir_node->vfid, NULL, 0, 1, &err);
		if (dir_node->vofid == NULL) {
			return (err);
		}
	}
	ofid = dir_node->vofid;

	err = p9_client_file_create(ofid, name, perm, mode, extension);
	if (err != 0) {
		p9_debug(ERROR, "p9_client_fcreate failed %d\n", err);
		goto out;
	}

	/* If its not hardlink only then do the walk, else we are done. */
	if (!(perm & P9PROTO_DMLINK)) {
		/*
		 * Do the lookup part and add the vnode, virtfs_node. Note that vpp
		 * is filled in here.
		 */
		newfid = p9_client_walk(dir_node->vfid, name, cnp->cn_namelen, 1, &err);
		if (newfid != NULL) {
			err = virtfs_vget_common(mp, NULL, cnp->cn_lkflags, newfid, vpp);
			if (err != 0)
				goto out;
		} else {
			/* Not found return NOENTRY.*/
			goto out;
		}

		if ((cnp->cn_flags & MAKEENTRY) != 0)
			cache_enter(VIRTFS_NTOV(dir_node), *vpp, cnp);
	}
	p9_debug(VOPS, "created file under vp %p node %p fid %d\n", *vpp, dir_node,
		(uintmax_t)dir_node->vfid->fid);
	/* Clunk the open ofid. */
	if (ofid != NULL) {
		(void)p9_client_clunk(ofid);
		dir_node->vofid = NULL;
	}

	return (0);
out:
	if (ofid != NULL)
		(void)p9_client_clunk(ofid);
	dir_node->vofid = NULL;

	if (newfid != NULL)
		(void)p9_client_clunk(newfid);

	return (err);
}

/*
 * virtfs_create is the main file creation vop. Make the permissions of the new file
 * and call the create_common common code to complete the create.
 */

static int
virtfs_create(struct vop_create_args *ap)
{
	struct vnode *dvp = ap->a_dvp;
	struct vnode **vpp = ap->a_vpp;
	struct componentname *cnp = ap->a_cnp;
	uint32_t mode = MAKEIMODE(ap->a_vap->va_type, ap->a_vap->va_mode);
	struct virtfs_node *dir_node = VIRTFS_VTON(dvp);
	struct virtfs_inode *inode = &dir_node->inode;
	uint32_t perm;
	int ret = 0;

	p9_debug(VOPS, "%s: dvp %p\n", __func__, dvp);

	perm = virtfs_unix2p9_mode(mode);

	ret = create_common(dir_node, cnp, NULL, perm, P9PROTO_ORDWR, vpp);
	if (ret == 0) {
		VIRTFS_INCR_LINKS(inode);
	}

	return (ret);
}

/*
 * virtfs_mkdir is the main directory creation vop. Make the permissions of the new dir
 * and call the create_common common code to complete the create.
 */
static int
virtfs_mkdir(struct vop_mkdir_args *ap)
{
	struct vnode *dvp = ap->a_dvp;
	struct vnode **vpp = ap->a_vpp;
	struct componentname *cnp = ap->a_cnp;
	uint32_t mode = MAKEIMODE(ap->a_vap->va_type, ap->a_vap->va_mode);
	struct virtfs_node *dir_node = VIRTFS_VTON(dvp);
	struct virtfs_inode *inode = &dir_node->inode;
	uint32_t perm;
	int ret = 0;

	p9_debug(VOPS, "%s: dvp %p\n", __func__, dvp);

	perm = virtfs_unix2p9_mode(mode | S_IFDIR);

	ret = create_common(dir_node, cnp, NULL, perm, P9PROTO_ORDWR, vpp);

	if (ret == 0)
		VIRTFS_INCR_LINKS(inode);
	return (ret);
}

/*
 * virtfs_mknod is the main node creation vop. Make the permissions of the new node
 * and call the create_common common code to complete the create.
 */
static int
virtfs_mknod(struct vop_mknod_args *ap)
{
	struct vnode *dvp = ap->a_dvp;
	struct vnode **vpp = ap->a_vpp;
	struct componentname *cnp = ap->a_cnp;
	uint32_t mode = MAKEIMODE(ap->a_vap->va_type, ap->a_vap->va_mode);
	struct virtfs_node *dir_node = VIRTFS_VTON(dvp);
	struct virtfs_inode *inode = &dir_node->inode;
	uint32_t perm;
	int ret = 0;

	p9_debug(VOPS, "%s: dvp %p\n", __func__, dvp);

	perm = virtfs_unix2p9_mode(mode);

	ret = create_common(dir_node, cnp, NULL, perm, P9PROTO_OREAD, vpp);

	if (ret == 0) {
		VIRTFS_INCR_LINKS(inode);
	}

	return (ret);
}

/* Converting open mode permissions to p9 */
static int
virtfs_uflags_mode(int uflags, int extended)
{
	uint32_t ret = 0;

	/* Convert first to O flags.*/
	uflags = OFLAGS(uflags);

	switch (uflags & 3) {

	case O_RDONLY:
		ret = P9PROTO_OREAD;
		break;

	case O_WRONLY:
		ret = P9PROTO_OWRITE;
		break;

	case O_RDWR:
		ret = P9PROTO_ORDWR;
		break;
	}

	if (extended) {
		if (uflags & O_EXCL)
			ret |= P9PROTO_OEXCL;

		if (uflags & O_APPEND)
			ret |= P9PROTO_OAPPEND;
	}

	return (ret);
}

/*
 * Virtfs_open is the main open vop for every file open. If the file is already
 * open then just increment the v_open and return. Reload all stats to get it
 * right first. If there is no open fid for this file, there needs to be a
 * client_walk which creates a new open fid for this file. Once we have a open fid,
 * call the open on this file with the mode creating the vobject.
 */
static int
virtfs_open(struct vop_open_args *ap)
{
	int error = 0;
	struct vnode *vp = ap->a_vp;
	struct virtfs_node *np = VIRTFS_VTON(vp);
	struct p9_fid *fid = np->vfid;
	size_t filesize;
	uint32_t mode;

	p9_debug(VOPS, "virtfs_open \n");

        error = virtfs_reload_stats(vp);
        if (error != 0)
                return (error);

	ASSERT_VOP_LOCKED(vp, __func__);
	/*
	 * Invalidate the pages of the vm_object cache if the file is modified
	 * based on the flag set in reload stats
	 */
        if (vp->v_type == VREG && (np->flags & VIRTFS_NODE_MODIFIED) != 0) {
                vinvalbuf(vp, 0, 0, 0);
                np->flags &= ~VIRTFS_NODE_MODIFIED;
        }

	if (np->v_opens > 0) {
		np->v_opens++;
		return (0);
	}

	/*
	 * According to 9p protocol, we cannot do Fileops on an already opened
	 * file. So we have to clone a new fid by walking and then use the open fids
	 * to do the open.
	 */
	if (np->vofid == NULL) {
		/*vofid is the open fid for this file.*/
		np->vofid = p9_client_walk(np->vfid,
		     NULL, 0, 1, &error);
		if (np->vofid == NULL) {
			return error;
		}
	}
	fid = np->vofid;
	filesize = np->inode.i_size;
	mode = virtfs_uflags_mode(ap->a_mode, 1);

	error = p9_client_open(fid, mode);
	if (error == 0) {
		np->v_opens = 1;
		vnode_create_vobject(vp, filesize, ap->a_td);
	}

	return (error);
}

/*
 * virtfs_close is the opposite of virtfs_open. Close the open references. Once reference
 * becomes 0, clunk the open fid, which means closing the file. Clunk never cares about
 * error code. If it fails, it will be fixed in the next mount and there might be some
 * inconsistent state which will be handled by the server.
 */
static int
virtfs_close(struct vop_close_args *ap)
{
	struct virtfs_node *np = VIRTFS_VTON(ap->a_vp);

	if (np == NULL) {
		return 0;
	}

	p9_debug(VOPS, "%s(fid %d opens %d)\n", __func__, np->vfid->fid, np->v_opens);
	np->v_opens--;
	if (np->v_opens == 0) {
		/* clean up the open fid */
		(void)p9_client_clunk(np->vofid);
		np->vofid = NULL;
	}

	return (0);
}

/* Helper for checking if fileops are possible on this file*/
static int
virtfs_check_possible(struct vnode *vp, struct vattr *vap, mode_t mode)
{

	/* Check if we are allowed to write */
	switch (vap->va_type) {
	case VDIR:
	case VLNK:
	case VREG:
		/*
		 * Normal nodes: check if we're on a read-only mounted
		 * file system and bail out if we're trying to write.
		 */
		if ((mode & VMODIFY_PERMS) && (vp->v_mount->mnt_flag & MNT_RDONLY))
			return (EROFS);
		break;
	case VBLK:
	case VCHR:
	case VSOCK:
	case VFIFO:
		/*
		 * Special nodes: even on read-only mounted file systems
		 * these are allowed to be written to if permissions allow.
		 */
		break;
	default:
		/* No idea what this is */
		return (EINVAL);
	}

	return (0);
}

/*
 * Checks the access permissions of the file.
 */
static int
virtfs_access(struct vop_access_args *ap)
{
	struct vnode *vp = ap->a_vp;
	accmode_t accmode = ap->a_accmode;
	struct ucred *cred = ap->a_cred;
	struct vattr vap;
	int error;

	p9_debug(VOPS,"virtfs_access \n");

	/* make sure getattr is working correctly and is defined.*/
	error = VOP_GETATTR(vp, &vap, NULL);
	if (error != 0)
		return (error);

	error = virtfs_check_possible(vp, &vap, accmode);
	if (error != 0)
		return (error);

	/* Call the Generic Access check in VOPS*/
	error = vaccess(vp->v_type, vap.va_mode, vap.va_uid, vap.va_gid, accmode,
#if __FreeBSD_version >= 1300105
	    cred);
#else
	    cred, NULL);
#endif

	return (error);
}

/*
 * Reload_stats does a client_stat on the server to re-read the file stats.
 * This stat structure is updated to the in memory inode structure of virtfs_node
 * which can be read anytime by getattr.
 */
int
virtfs_reload_stats(struct vnode *vp)
{
	struct p9_wstat *stat = NULL;
	int error = 0;
	struct virtfs_node *node = VIRTFS_VTON(vp);

	/* allocation shouldnt fail as we have WAITOK flag. */
	stat = uma_zalloc(virtfs_stat_zone, M_WAITOK | M_ZERO);
	error = p9_client_stat(node->vfid, &stat);

	if (error != 0) {
		p9_debug(ERROR, "p9_client_stat failed to reload stats\n");
		goto out;
	}

	/* Init the vnode with the disk info */
	virtfs_stat_vnode_u(stat, vp);
out:
	if (stat != NULL) {
		uma_zfree(virtfs_stat_zone, stat);
	}

	return (error);
}

/*
 * getattr vop which reads the current inode values into the vap attr.
 * For now we are reloading the stats from the server. We might probably
 * cache it later.
 */
static int
virtfs_getattr(struct vop_getattr_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct vattr *vap = ap->a_vap;
	struct virtfs_node *node = VIRTFS_VTON(vp);
	struct virtfs_inode *inode = &node->inode;
        struct virtfs_mount *vmp = VFSTOP9(vp->v_mount);
        uint64_t bsize, filesize;
	int error;
	int type;

	p9_debug(VOPS, "getattr %u %u\n", inode->i_mode, IFTOVT(inode->i_mode));

	/* Reload our stats once to get the right values.*/
	error = virtfs_reload_stats(vp);
	if (error != 0) {
		p9_debug(ERROR, "virtfs_reload_stats failed %d\n", error);
		return (error);
	}

	/* Basic info */
	VATTR_NULL(vap);

	vap->va_atime.tv_sec = inode->i_atime;
	vap->va_mtime.tv_sec = inode->i_mtime;
	type = IFTOVT(inode->i_mode);
	vap->va_type = IFTOVT(inode->i_mode);
	vap->va_mode = inode->i_mode;
	vap->va_uid = inode->n_uid;
	vap->va_gid = inode->n_gid;
	vap->va_fsid = vp->v_mount->mnt_stat.f_fsid.val[0];
	vap->va_size = inode->i_size;
	vap->va_nlink = inode->i_links_count;
	vap->va_blocksize = PAGE_SIZE;
	vap->va_fileid = inode->n_ino;
	vap->va_flags = inode->i_flags;
	vap->va_gen = 0;
	vap->va_filerev = 0;
	vap->va_vaflags = 0;
        filesize = inode->i_size;
        bsize = vp->v_mount->mnt_stat.f_bsize;
        vap->va_bytes = vmp->virtfs_filesize2bytes(filesize, bsize);

	return (0);
}

/* Converting a p9 mode to standard unix permissions*/
static int
virtfs_mode2perm(struct virtfs_session *ses,
    struct p9_wstat *stat)
{
	uint32_t res;
	uint32_t mode = stat->mode;

	/* Get the correct perms */
	res = mode & ALLPERMS;

	if ((mode & P9PROTO_DMSETUID) == P9PROTO_DMSETUID)
		res |= S_ISUID;

	if ((mode & P9PROTO_DMSETGID) == P9PROTO_DMSETGID)
		res |= S_ISGID;

	if ((mode & P9PROTO_DMSETVTX) == P9PROTO_DMSETVTX)
		res |= S_ISVTX;

	return (res);
}

/* Converting a standard FreeBSD permission to p9.*/
static uint32_t
virtfs_unix2p9_mode(uint32_t mode)
{
	uint32_t res = mode & 0777;

	if (S_ISDIR(mode))
		res |= P9PROTO_DMDIR;
	if (S_ISSOCK(mode))
		res |= P9PROTO_DMSOCKET;
	if (S_ISFIFO(mode))
		res |= P9PROTO_DMNAMEDPIPE;
	if ((mode & S_ISUID) == S_ISUID)
		res |= P9PROTO_DMSETUID;
	if ((mode & S_ISGID) == S_ISGID)
		res |= P9PROTO_DMSETGID;
	if ((mode & S_ISVTX) == S_ISVTX)
		res |= P9PROTO_DMSETVTX;

	return (res);
}

/* Converting a 9p mode to unix*/
static int
virtfs_9p2unix_mode(uint32_t mode, struct virtfs_inode *inode)
{

	if ((mode & P9PROTO_DMDIR) == P9PROTO_DMDIR)
		inode->i_mode |= S_IFDIR;
	else if (mode & P9PROTO_DMSYMLINK)
		inode->i_mode |= S_IFLNK;
	else if (mode & P9PROTO_DMSOCKET)
		inode->i_mode |= S_IFSOCK;
	else if (mode & P9PROTO_DMNAMEDPIPE)
		inode->i_mode |= S_IFIFO;
	else
		inode->i_mode |= S_IFREG;

	return (0);
}

/* Reloading an in memory inode with the stats read from server. The u version*/
int
virtfs_stat_vnode_u(struct p9_wstat *stat, struct vnode *vp)
{
	struct virtfs_node *np = VIRTFS_VTON(vp);
	struct virtfs_inode *inode = &np->inode;
	struct virtfs_session *ses = np->virtfs_ses;
	uint32_t mode;

	ASSERT_VOP_LOCKED(vp, __func__);
	/* Update the pager size if file size changes on host */
        if (inode->i_size != stat->length) {
		inode->i_size = stat->length;
		if (vp->v_type == VREG)
			vnode_pager_setsize(vp, inode->i_size);
        }
	inode->i_type = stat->type;
	inode->i_dev = stat->dev;
	inode->i_mtime = stat->mtime;
	inode->i_atime = stat->atime;
	inode->i_name = stat->name;
	inode->n_uid = stat->n_uid;
	inode->n_gid = stat->n_gid;
	inode->n_muid = stat->n_muid;
	inode->i_extension = stat->extension;
	inode->i_uid = stat->uid;
	inode->i_gid = stat->gid;
	inode->i_muid = stat->muid;
	VIRTFS_SET_LINKS(inode);
	mode = virtfs_mode2perm(ses, stat);
	mode |= (inode->i_mode & ~ALLPERMS);
	inode->i_mode = mode;

	virtfs_9p2unix_mode(stat->mode, inode);
	vp->v_type = IFTOVT(inode->i_mode);
	ASSERT_VOP_LOCKED(vp, __func__);
	/* Setting a flag if file changes based on qid version */
        if (np->vqid.qid_version != stat->qid.version)
                np->flags |= VIRTFS_NODE_MODIFIED;
	memcpy(&np->vqid, &stat->qid, sizeof(stat->qid));

	return (0);
}

/*
 * Writing the current in memory inode stats into persistent stats structure
 * to write to the server.
 */
static int
virtfs_inode_to_wstat(struct virtfs_inode *inode, struct p9_wstat *wstat)
{

	wstat->length = inode->i_size;
	wstat->type = inode->i_type;
	wstat->dev = inode->i_dev;
	wstat->mtime = inode->i_mtime;
	wstat->atime = inode->i_atime;
	wstat->name = inode->i_name;
	wstat->n_uid = inode->n_uid;
	wstat->n_gid = inode->n_gid;
	wstat->n_muid = inode->n_muid;
	wstat->extension = inode->i_extension;
	wstat->uid = inode->i_uid;
	wstat->gid = inode->i_gid;
	wstat->muid = inode->i_muid;
	wstat->mode = virtfs_unix2p9_mode(inode->i_mode);

	return (0);
}

/* virtfs_chown is called whenever the chown is called on the file.*/
static int
virtfs_chown(struct vnode *vp, uid_t uid, gid_t gid, struct ucred *cred,
    struct thread *td)
{
	struct virtfs_node *node = VIRTFS_VTON(vp);
	struct virtfs_inode *inode = &node->inode;
	uid_t ouid;
	gid_t ogid;
	int error = 0;

	if (uid == (uid_t)VNOVAL)
		uid = inode->n_uid;
	if (gid == (gid_t)VNOVAL)
		gid = inode->n_gid;
	/*
	 * To modify the ownership of a file, must possess VADMIN for that
	 * file.
	 */
	if ((error = VOP_ACCESSX(vp, VWRITE_OWNER, cred, td)))
		return (error);
	/*
	 * To change the owner of a file, or change the group of a file to a
	 * group of which we are not a member, the caller must have
	 * privilege.
	 */
	if (((uid != inode->n_uid && uid != cred->cr_uid) ||
	    (gid != inode->n_gid && !groupmember(gid, cred))) &&
#if __FreeBSD_version >= 1300005
	    (error = priv_check_cred(cred, PRIV_VFS_CHOWN)))
#else
	    (error = priv_check_cred(cred, PRIV_VFS_CHOWN, 0)))
#endif
		return (error);

	ogid = inode->n_gid;
	ouid = inode->n_uid;

	inode->n_gid = gid;
	inode->n_uid = uid;

	if ((inode->i_mode & (ISUID | ISGID)) &&
	    (ouid != uid || ogid != gid)) {

#if __FreeBSD_version >= 1300005
		if (priv_check_cred(cred, PRIV_VFS_RETAINSUGID))
#else
		if (priv_check_cred(cred, PRIV_VFS_RETAINSUGID, 0))
#endif
			inode->i_mode &= ~(ISUID | ISGID);
	}
	p9_debug(VOPS, "%s: vp %p, cred %p, td %p - ret OK\n", __func__, vp, cred, td);

	return (0);
}

/*
 * Chmod is called on the file. This updates the in memory inode with all chmod new
 * permissions/mode. Typically a setattr is called to update it to server.
 */
static int
virtfs_chmod(struct vnode *vp, uint32_t  mode, struct ucred *cred, struct thread *td)
{
	struct virtfs_node *node = VIRTFS_VTON(vp);
	struct virtfs_inode *inode = &node->inode;
	uint32_t nmode;
	int error = 0;

	p9_debug(VOPS, "%s: vp %p, mode %x, cred %p, td %p\n",  __func__, vp, mode, cred, td);
	/*
	 * To modify the permissions on a file, must possess VADMIN
	 * for that file.
	 */
	if ((error = VOP_ACCESS(vp, VADMIN, cred, td)))
		return (error);

	/*
	 * Privileged processes may set the sticky bit on non-directories,
	 * as well as set the setgid bit on a file with a group that the
	 * process is not a member of. Both of these are allowed in
	 * jail(8).
	 */
	if (vp->v_type != VDIR && (mode & S_ISTXT)) {
#if __FreeBSD_version >= 1300005
		if (priv_check_cred(cred, PRIV_VFS_STICKYFILE))
#else
		if (priv_check_cred(cred, PRIV_VFS_STICKYFILE, 0))
#endif
			return (EFTYPE);
	}
	if (!groupmember(inode->n_gid, cred) && (mode & ISGID)) {
#if __FreeBSD_version >= 1300005
		error = priv_check_cred(cred, PRIV_VFS_SETGID);
#else
		error = priv_check_cred(cred, PRIV_VFS_SETGID, 0);
#endif
		if (error)
			return (error);
	}

	/*
	 * Deny setting setuid if we are not the file owner.
	 */
	if ((mode & ISUID) && inode->n_uid != cred->cr_uid) {
#if __FreeBSD_version >= 1300005
		error = priv_check_cred(cred, PRIV_VFS_ADMIN);
#else
		error = priv_check_cred(cred, PRIV_VFS_ADMIN, 0);
#endif
		if (error)
			return (error);
	}
	nmode = inode->i_mode;
	nmode &= ~ALLPERMS;
	nmode |= (mode & ALLPERMS);
	inode->i_mode = nmode;

	p9_debug(VOPS, "%s: to mode %x  %d \n ", __func__, nmode, error);

	return (error);
}

/*
 * setattr is called when any value on the attr changes. Also called
 * while creating new files. This saves the attributes to peristent
 * store. client_wstat is called to do the final inode writes to
 * the server.
 */
static int
virtfs_setattr(struct vop_setattr_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct vattr *vap = ap->a_vap;
	struct virtfs_node *node = VIRTFS_VTON(vp);
	struct virtfs_inode *inode = &node->inode;
	struct ucred *cred = ap->a_cred;
	struct thread *td = curthread;
	uint64_t flags;
	struct p9_wstat *wstat = NULL;
	int error = 0;

	wstat = uma_zalloc(virtfs_stat_zone, M_WAITOK | M_ZERO);

	if ((vap->va_type != VNON) || (vap->va_nlink != VNOVAL) ||
	    (vap->va_fsid != VNOVAL) || (vap->va_fileid != VNOVAL) ||
	    (vap->va_blocksize != VNOVAL) || (vap->va_rdev != VNOVAL) ||
	    (vap->va_bytes != VNOVAL) || (vap->va_gen != VNOVAL)) {

		p9_debug(ERROR, "%s: unsettable attribute\n", __func__);
		error = EINVAL;
		goto out;
	}

	if (vap->va_flags != VNOVAL) {

		p9_debug(VOPS, "%s: vp:%p td:%p flags:%lx\n", __func__, vp, td, vap->va_flags);
		if (vp->v_mount->mnt_flag & MNT_RDONLY)
			return (EROFS);
		/*
		 * Callers may only modify the file flags on objects they
		 * have VADMIN rights for.
		 */
		if ((error = VOP_ACCESS(vp, VADMIN, cred, td)))
			return (error);
		/*
		 * Unprivileged processes are not permitted to unset system
		 * flags, or modify flags if any system flags are set.
		 * Privileged non-jail processes may not modify system flags
		 * if securelevel > 0 and any existing system flags are set.
		 * Privileged jail processes behave like privileged non-jail
		 * processes if the security.jail.chflags_allowed sysctl is
		 * is non-zero; otherwise, they behave like unprivileged
		 * processes.
		 */

		flags = inode->i_flags;
#if __FreeBSD_version >= 1300005
		if (!priv_check_cred(cred, PRIV_VFS_SYSFLAGS)) {
#else
		if (!priv_check_cred(cred, PRIV_VFS_SYSFLAGS, 0)) {
#endif
			if (flags & (SF_NOUNLINK | SF_IMMUTABLE | SF_APPEND)) {
				error = securelevel_gt(cred, 0);
			if (error)
				return (error);
			}

			/* Snapshot flag cannot be set or cleared */
			if (((vap->va_flags & SF_SNAPSHOT) != 0 &&
			    (flags & SF_SNAPSHOT) == 0) ||
			    ((vap->va_flags & SF_SNAPSHOT) == 0 &&
			    (flags & SF_SNAPSHOT) != 0))
				return (EPERM);
			inode->i_flags = vap->va_flags;
		} else {

			if (flags & (SF_NOUNLINK | SF_IMMUTABLE | SF_APPEND) ||
			    (vap->va_flags & UF_SETTABLE) != vap->va_flags)
				return (EPERM);
			flags &= SF_SETTABLE;
			flags |= (vap->va_flags & UF_SETTABLE);
			inode->i_flags = flags;
		}
		if (vap->va_flags & (IMMUTABLE | APPEND))
			return (0);
	}
	if (inode->i_flags & (IMMUTABLE | APPEND))
		return (EPERM);

	/* Check if we need to change the ownership of the file*/
	if (vap->va_uid != (uid_t)VNOVAL || vap->va_gid != (gid_t)VNOVAL) {
		if (vp->v_mount->mnt_flag & MNT_RDONLY)
			return EROFS;

		p9_debug(VOPS, "%s: vp:%p td:%p uid/gid %x/%x\n", __func__,
		    vp, td, vap->va_uid, vap->va_gid);

		error = virtfs_chown(vp, vap->va_uid, vap->va_gid, cred, td);
		if (error)
			goto out;
	}

	/* Check for mode changes */
	if (vap->va_mode != (mode_t)VNOVAL) {

		if (vp->v_mount->mnt_flag & MNT_RDONLY) {
			error = EROFS;
			goto out;
		}

		p9_debug(VOPS, "%s: vp:%p td:%p mode %x\n", __func__, vp, td,
		    vap->va_mode);

		error = virtfs_chmod(vp, (int)vap->va_mode, cred, td);

		if (error)
			goto out;
	}

	if (vap->va_atime.tv_sec != VNOVAL || vap->va_mtime.tv_sec != VNOVAL) {

		p9_debug(VOPS, "%s: vp:%p td:%p time a/m %jx/%jx/\n",
		    __func__, vp, td, (uintmax_t)vap->va_atime.tv_sec,
		    (uintmax_t)vap->va_mtime.tv_sec);

		/* Update the virtfs_inode times */
		virtfs_itimes(vp);
	}
	/* Write the inode structure values into wstat */
	virtfs_inode_to_wstat(inode, wstat);
	error = p9_client_wstat(node->vfid, wstat);
out:
	if (wstat) {
		uma_zfree(virtfs_stat_zone, wstat);
	}
	p9_debug(VOPS, "error code for p9_client_wstat %d \n",error);

	return (error);
}

/*
 * An IO buffer is used to to do any transfer. The user uio is the vfs structure we
 * need to copy data into. While resid(uio_resid) exists, we call client_read
 * to read data from offset( offset into the file) in the open fid for the file
 * into the io_buffer. This io_buffer is used to transfer data into uio to complete
 * it to the VFS.
 */
static int
virtfs_read(struct vop_read_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct uio *uio = ap->a_uio;
	struct virtfs_node *np = VIRTFS_VTON(vp);
	uint64_t offset;
	int64_t ret;
	uint64_t resid;
	uint32_t count;
	int error = 0;
	char *io_buffer;
	uint64_t filesize;

	if (vp->v_type == VCHR || vp->v_type == VBLK)
		return (EOPNOTSUPP);

	if (vp->v_type != VREG)
		return (EISDIR);

	if (uio->uio_resid == 0)
		return (0);

	if (uio->uio_offset < 0)
		return (EINVAL);

	/* where in the file are we to start reading */
	offset = uio->uio_offset;
	filesize = np->inode.i_size;
	if(uio->uio_offset >= filesize)
		return (0);

	p9_debug(VOPS, "virtfs_read called %lu at %lu\n",
	    uio->uio_resid, (uintmax_t)uio->uio_offset);

	/* Work with a local buffer from the pool for this vop */

	io_buffer = uma_zalloc(virtfs_io_buffer_zone, M_WAITOK | M_ZERO);
	while ((resid = uio->uio_resid) > 0) {

		if (offset >= filesize)
			break;

		count = MIN(filesize - uio->uio_offset , resid);

		if (count == 0)
			break;

		/* Copy count bytes into the uio */
		ret = p9_client_read(np->vofid, offset, count, io_buffer);
		/*
		 * This is the only place in the entire VIRTFS were we check the error
		 * for < 0 as p9_client_read/write return the number of bytes instead of
		 * an error code. In this case if ret is < 0, it means there is an IO error.
		 */
		if (ret < 0)
			goto out;

		error = uiomove(io_buffer, ret, uio);

		if (error != 0)
			goto out;

		offset += ret;
	}
	uio->uio_offset = offset;
out:
	if (ret < 0)
		error = -ret;

	uma_zfree(virtfs_io_buffer_zone, io_buffer);

	return (error);
}

/*
 * uio points to the data to be writtrn into the file. This data is copied first
 * from uio into io_buffer. This buffer is used to do the client_write to the fid
 * of the file from offset for count bytes. Updates the filesize after that.
 */
static int
virtfs_write(struct vop_write_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct uio *uio = ap->a_uio;
	struct virtfs_node *node = VIRTFS_VTON(vp);
	uint64_t off, offset;
	int64_t ret;
	uint64_t resid;
	uint32_t count;
	int error = 0, ioflag;
	uint64_t file_size;
	char *io_buffer;

	vp = ap->a_vp;
	uio = ap->a_uio;
	ioflag = ap->a_ioflag;
	node = VIRTFS_VTON(vp);

	p9_debug(VOPS, "virtfs_write called %#zx at %#jx\n",
	    uio->uio_resid, (uintmax_t)uio->uio_offset);

	if (uio->uio_offset < 0)
		return (EINVAL);
	if (uio->uio_resid == 0)
		return (0);

	file_size = node->inode.i_size;

	switch (vp->v_type) {
	case VREG:
		if (ioflag & IO_APPEND)
			uio->uio_offset = file_size;
			break;
	case VDIR:
		return (EISDIR);
	case VLNK:
		break;
	default:
		panic("%s: bad file type vp: %p", __func__, vp);
	}

	resid = uio->uio_resid;
	offset = uio->uio_offset;
	error = 0;

	io_buffer = uma_zalloc(virtfs_io_buffer_zone, M_WAITOK | M_ZERO);
	while ((resid = uio->uio_resid) > 0) {

                off = 0;
		count = MIN(resid, VIRTFS_IOUNIT);
		error = uiomove(io_buffer, count, uio);

		if (error != 0) {
			p9_debug(ERROR, "uiomove error in virtfs_write\n");
			goto out;
		}

		/* While count still exists, keep writing.*/
		while (count > 0) {
			/* Copy count bytes from the uio */
			ret = p9_client_write(node->vofid, offset, count,
                                io_buffer + off);
			if (ret < 0)
				goto out;
			p9_debug(VOPS, "virtfs_write called %#zx at %#jx\n",
			    uio->uio_resid, (uintmax_t)uio->uio_offset);

                        off += ret;
			offset += ret;
			count -= ret;
		}
	}
	/* Update the fields in the node to reflect the change*/
	if (file_size < uio->uio_offset + uio->uio_resid) {
		node->inode.i_size = uio->uio_offset + uio->uio_resid;
		vnode_pager_setsize(vp, uio->uio_offset + uio->uio_resid);

		/* update the modified timers. */
		virtfs_itimes(vp);
	}
out:
	if (ret < 0)
		error = -ret;

	uma_zfree(virtfs_io_buffer_zone, io_buffer);

	return (error);
}

/*
 * Remove wrapper is called by all rm related vops( ex for rmdir, rm).
 * This is common code for those. It performs the client_remove op to
 * send messages to remove the node's fid on the server. After that, it
 * does a node metadata cleanup on client side.
 */
static int
remove_common(struct virtfs_node *node)
{
	int retval = 0;

	retval = p9_client_remove(node->vfid);
	node->vfid = NULL;
	retval = virtfs_cleanup(node);

	return (retval);
}

/* Remove vop for all files. call common code for remove and adjust links */
static int
virtfs_remove(struct vop_remove_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct virtfs_node *node = VIRTFS_VTON(vp);
	struct vnode *dvp = ap->a_dvp;
	struct virtfs_node *dir_node = VIRTFS_VTON(dvp);
	struct virtfs_inode *dir_ino = &dir_node->inode;
	int ret = 0;

	p9_debug(VOPS, "%s: vp %p node %p \n", __func__, vp, node);

	if (vp->v_type == VDIR)
		return (EISDIR);

	ret = remove_common(node);

	if (ret == 0) {
		VIRTFS_DECR_LINKS(dir_ino);
	}

	return (ret);
}

/* Remove vop for all directories. Call common code for remove and adjust links */
static int
virtfs_rmdir(struct vop_rmdir_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct virtfs_node *node = VIRTFS_VTON(vp);
	struct vnode *dvp = ap->a_dvp;
	struct virtfs_node *dir_node = VIRTFS_VTON(dvp);
	struct virtfs_inode *dir_ino = &dir_node->inode;
	int ret = 0;

	p9_debug(VOPS, "%s: vp %p node %p \n", __func__, vp, node);

	ret = remove_common(node);

	if (ret == 0) {
		VIRTFS_DECR_LINKS(dir_ino);
	}

	return (ret);
}

/*
 * Creation of symlinks. Make the permissions and call create_common code
 * for Soft links.
 */
static int
virtfs_symlink(struct vop_symlink_args *ap)
{
	struct vnode *dvp = ap->a_dvp;
	struct vnode **vpp = ap->a_vpp;
	struct componentname *cnp = ap->a_cnp;
	uint32_t mode = MAKEIMODE(ap->a_vap->va_type, ap->a_vap->va_mode);
	struct virtfs_node *dir_node = VIRTFS_VTON(dvp);
	struct virtfs_inode *inode = &dir_node->inode;
	uint32_t perm;
	int ret = 0;

	p9_debug(VOPS, "%s: dvp %p\n", __func__, dvp);

	perm = virtfs_unix2p9_mode(mode);

	ret = create_common(dir_node, cnp, NULL, P9PROTO_DMSYMLINK | perm, P9PROTO_OREAD, vpp);

	if (ret == 0) {
		VIRTFS_INCR_LINKS(inode);
	}

	return (ret);
}

static ino_t
virtfs_qid2ino(struct p9_qid *qid)
{
	uint64_t path = qid->path;
	ino_t i = 0;

	if (sizeof(ino_t) == sizeof(path))
		memcpy(&i, &path, sizeof(ino_t));
	else
		i = (ino_t) (path ^ (path >> 32));

	return (i);
}

/*
 * Readdir does a read on a directory to list its contents, all the files and directories.
 * First an entire 8k data is read into the io_buffer. This buffer is parsed to make dirent.
 * and added to uio buffer to complete to the VFS.
 *
 */
static int
virtfs_readdir(struct vop_readdir_args *ap)
{
	struct uio *uio = ap->a_uio;
	struct vnode *vp = ap->a_vp;
	struct dirent cde;
	int64_t offset = 0;
	uint64_t diroffset = 0;
	struct virtfs_node *np = VIRTFS_VTON(ap->a_vp);
	int error = 0;
	int32_t count = 0;
	struct p9_client *clnt = np->virtfs_ses->clnt;
	struct p9_dirent dent;
	char *io_buffer;

	if (ap->a_uio->uio_iov->iov_len <= 0)
		return (EINVAL);

	if (vp->v_type != VDIR)
		return (ENOTDIR);

	p9_debug(VOPS, "virtfs_readdir resid %zd\n",uio->uio_resid);

	io_buffer = uma_zalloc(virtfs_io_buffer_zone, M_WAITOK);

	/* We havnt reached the end yet. read more. */
	diroffset = uio->uio_offset;
	while (uio->uio_resid >= sizeof(struct dirent)) {
		/*
		 * We need to read more data as what is indicated by filesize because
		 * filesize is based on data stored in struct dirent structure but
		 * we read data in struct p9_dirent format which has different size.
		 * Hence we read max data(VIRTFS_IOUNIT) everytime from host, convert
		 * it into struct dirent structure and send it back.
		 */
		count = VIRTFS_IOUNIT;
		bzero(io_buffer, VIRTFS_MTU);
		count = p9_client_readdir(np->vofid, (char *)io_buffer,
			diroffset, count);

		if (count == 0)
			break;

		if (count < 0) {
			error = EIO;
			goto out;
		}

		offset = 0;
		while (offset + QEMU_DIRENTRY_SZ <= count) {

			/*
			 * Read and make sense out of the buffer in one dirent
			 * This is part of 9p protocol read. This reads one p9_dirent,
			 * appends it to dirent(FREEBSD specifc) and continues to parse the buffer.
			 */
			bzero(&dent, sizeof(dent));
			offset = p9_dirent_read(clnt, io_buffer, offset, count,
				&dent);
			if (offset < 0 || offset > count) {
				error = EIO;
				goto out;
			}

			/*
			 * If there isn't enough space in the uio to return a
			 * whole dirent, break off read
			 */
			if (uio->uio_resid < GENERIC_DIRSIZ(&cde))
				break;

			bzero(&cde, sizeof(cde));
			strncpy(cde.d_name, dent.d_name, dent.len);
			cde.d_fileno = virtfs_qid2ino(&dent.qid) + offset;
			cde.d_type = dent.d_type;
			cde.d_namlen = dent.len;
			cde.d_reclen = GENERIC_DIRSIZ(&cde);

			/* Transfer */
			error = uiomove(&cde, GENERIC_DIRSIZ(&cde), uio);
			if (error != 0) {
				error = EIO;
				goto out;
			}
			diroffset = dent.d_off;
		}
	}
	/* Pass on last transferred offset */
	uio->uio_offset = diroffset;

out:
	uma_zfree(virtfs_io_buffer_zone, io_buffer);

	return (error);
}

/*
 * Strategy for doing buffer IO. The buffer in IO is mapped to a created uio and then a
 * client_write/client_read is performed the same way as virtfs_read and virtfs_write.
 */
static int
virtfs_strategy(struct vop_strategy_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct buf *bp = ap->a_bp;
	struct uio *uiov;
	struct iovec io;
	int error = 0;
	uint64_t off, offset;
	uint64_t filesize;
	uint64_t resid;
	uint32_t count;
	uint64_t ret;
	struct virtfs_node *node = VIRTFS_VTON(vp);
	char *io_buffer;

	filesize = node->inode.i_size;
	uiov = malloc(sizeof(struct uio), M_P9UIOV, M_WAITOK);
	uiov->uio_iov = &io;
	uiov->uio_iovcnt = 1;
	uiov->uio_segflg = UIO_SYSSPACE;
	io_buffer = uma_zalloc(virtfs_io_buffer_zone, M_WAITOK | M_ZERO);

	if (bp->b_iocmd == BIO_READ) {
		io.iov_len = uiov->uio_resid = bp->b_bcount;
		io.iov_base = bp->b_data;
		uiov->uio_rw = UIO_READ;

		switch (vp->v_type) {

		case VREG:
		{
			uiov->uio_offset = ((off_t)bp->b_blkno) * DEV_BSIZE;

			if (uiov->uio_resid) {
				int left = uiov->uio_resid;
				int nread = bp->b_bcount - left;

				if (left > 0)
					bzero((char *)bp->b_data + nread, left);
			}
			/* where in the file are we to start reading */
			offset = uiov->uio_offset;
			if (uiov->uio_offset >= filesize)
				goto out;

			while ((resid = uiov->uio_resid) > 0) {
				if (offset >= filesize)
					break;
				count = min(filesize - uiov->uio_offset, resid);
				if (count == 0)
					break;

				p9_debug(VOPS, "virtfs_strategy read called %#zx at %#jx\n",
				    uiov->uio_resid, (uintmax_t)uiov->uio_offset);

				/* Copy count bytes into the uio */
				ret = p9_client_read(node->vofid, offset, count, io_buffer);
				error = uiomove(io_buffer, ret, uiov);

				if (error != 0)
					goto out;
				offset += ret;
			}
			break;
		}
		default:
			printf("vfs:  type %x unexpected\n", vp->v_type);
			break;
		}
	} else {
		if (bp->b_dirtyend > bp->b_dirtyoff) {
			io.iov_len = uiov->uio_resid = bp->b_dirtyend - bp->b_dirtyoff;
			uiov->uio_offset = ((off_t)bp->b_blkno) * PAGE_SIZE + bp->b_dirtyoff;
			io.iov_base = (char *)bp->b_data + bp->b_dirtyoff;
			uiov->uio_rw = UIO_WRITE;

			if (uiov->uio_offset < 0) {
				error = EINVAL;
				goto out;
			}

			if (uiov->uio_resid == 0)
				goto out;

			resid = uiov->uio_resid;
			offset = uiov->uio_offset;
			error = 0;

			while ((resid = uiov->uio_resid) > 0) {
                                off = 0;
				count = MIN(resid, VIRTFS_IOUNIT);
				error = uiomove(io_buffer, count, uiov);
				if (error != 0) {
					goto out;
				}

				while (count > 0) {
					/* Copy count bytes from the uio */
					ret = p9_client_write(node->vofid, offset, count,
                                                io_buffer + off);
					if (ret < 0)
						goto out;

					p9_debug(VOPS, "virtfs_strategy write called %#zx at %#jx\n",
				    	    uiov->uio_resid, (uintmax_t)uiov->uio_offset);
                                        off += ret;
					offset += ret;
					count -= ret;
				}
			}

			/* Update the fields in the node to reflect the change */
			if (filesize < uiov->uio_offset + uiov->uio_resid) {
				node->inode.i_size = uiov->uio_offset + uiov->uio_resid;
				vnode_pager_setsize(vp, uiov->uio_offset + uiov->uio_resid);
				/* update the modified timers. */
				virtfs_itimes(vp);
			}
		} else {
			 bp->b_resid = 0;
			 goto out1;
		}
	}
out:
	/* Set the error */
	if (error != 0) {
		bp->b_error = error;
		bp->b_ioflags |= BIO_ERROR;
	}
	bp->b_resid = uiov->uio_resid;
out1:
	bufdone(bp);
	uma_zfree(virtfs_io_buffer_zone, io_buffer);
	free(uiov, M_P9UIOV);

	return (error);
}

struct vop_vector virtfs_vnops = {
	.vop_default =		&default_vnodeops,
	.vop_lookup =		virtfs_lookup,
	.vop_open =		virtfs_open,
	.vop_close =		virtfs_close,
	.vop_access =		virtfs_access,
	.vop_getattr =		virtfs_getattr,
	.vop_setattr =		virtfs_setattr,
	.vop_reclaim =		virtfs_reclaim,
	.vop_readdir =		virtfs_readdir,
	.vop_create =		virtfs_create,
	.vop_mknod =		virtfs_mknod,
	.vop_read =		virtfs_read,
	.vop_write =		virtfs_write,
	.vop_remove =		virtfs_remove,
	.vop_mkdir =		virtfs_mkdir,
	.vop_rmdir =		virtfs_rmdir,
	.vop_strategy =		virtfs_strategy,
	.vop_symlink =		virtfs_symlink,
};
