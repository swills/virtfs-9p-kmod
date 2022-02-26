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
/*-
 * 9P filesystem subroutines. This file consists of all the Non VFS subroutines.
 * It contains all of the functions related to the driver submission which form
 * the upper layer i.e, VirtFS driver. This will interact with the client to make
 * sure we have correct API calls in the header.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/uio.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/limits.h>
#include <sys/sysctl.h>
#include <sys/vnode.h>
#include "virtfs_proto.h"
#include <dev/virtio/virtio_fs_client.h>
#include <dev/virtio/virtio_fs_protocol.h>
#include <dev/virtio/virtio_fs_9p.h>
#include "virtfs.h"

int
virtfs_proto_dotl(struct virtfs_session *vses)
{

	return (vses->flags & VIRTFS_PROTO_2000L);
}

/* Initialize a VirtFS session */
struct p9_fid *
virtfs_init_session(struct mount *mp, int *error)
{
	struct virtfs_session *vses;
	struct virtfs_mount *virtmp;
	struct p9_fid *fid;
	char *access;

	virtmp = VFSTOP9(mp);
	vses = &virtmp->virtfs_session;
	vses->uid = P9_NONUNAME;
	vses->uname = P9_DEFUNAME;
	vses->aname = P9_DEFANAME;

	/*
	 * Create the client structure. Call into the driver to create
	 * driver structures for the actual IO transfer.
	 */
	vses->clnt = p9_client_create(mp, error, virtmp->mount_tag);

	if (vses->clnt == NULL) {
		p9_debug(ERROR, "problem initializing 9p client\n");
		return NULL;
	}
	/*
	 * Find the client version and cache the copy. We will use this copy
	 * throughout FS layer.
	 */
	if (p9_is_proto_dotl(vses->clnt))
		vses->flags |= VIRTFS_PROTO_2000L;
	else if (p9_is_proto_dotu(vses->clnt))
		vses->flags |= VIRTFS_PROTO_2000U;

	/* Set the access mode */
	access = vfs_getopts(mp->mnt_optnew, "access", error);
	if (access == NULL)
		vses->flags |= P9_ACCESS_USER;
	else if (!strcmp(access, "any"))
		vses->flags |= P9_ACCESS_ANY;
	else if (!strcmp(access, "single"))
		vses->flags |= P9_ACCESS_SINGLE;
	else if (!strcmp(access, "user"))
		vses->flags |= P9_ACCESS_USER;
	else {
		p9_debug(ERROR, "Unknown access mode\n");
		*error = EINVAL;
		goto out;
	}

	*error = 0;
	/* Attach with the backend host*/
	fid = p9_client_attach(vses->clnt, NULL, vses->uname, P9_NONUNAME,
	    vses->aname, error);
	vses->mnt_fid = fid;

	if (*error != 0) {
		p9_debug(ERROR, "cannot attach\n");
		goto out;
	}
	p9_debug(SUBR, "Attach successful fid :%p\n", fid);
	fid->uid = vses->uid;

	/* initialize the node list for the session */
	STAILQ_INIT(&vses->virt_node_list);
	VIRTFS_LOCK_INIT(vses);

	p9_debug(SUBR, "INIT session successful\n");

	return fid;
out:
	p9_client_destroy(vses->clnt);
	return NULL;
}

/* Begin to terminate a session */
void
virtfs_prepare_to_close(struct mount *mp)
{
	struct virtfs_session *vses;
	struct virtfs_mount *vmp;

	vmp = VFSTOP9(mp);
	vses = &vmp->virtfs_session;

	/* We are about to teardown, we dont allow anything other than clunk after this.*/
	p9_client_begin_disconnect(vses->clnt);
}

/* Shutdown a session */
void
virtfs_complete_close(struct mount *mp)
{
	struct virtfs_session *vses;
	struct virtfs_mount *vmp;

	vmp = VFSTOP9(mp);
	vses = &vmp->virtfs_session;

	/* Finish the close*/
	p9_client_disconnect(vses->clnt);
}


/* Call from unmount. Close the session. */
void
virtfs_close_session(struct mount *mp)
{
	struct virtfs_session *vses;
	struct virtfs_mount *vmp;
	struct virtfs_node *p, *tmp;

	vmp = VFSTOP9(mp);
	vses = &vmp->virtfs_session;

	/*
	 * Cleanup the leftover VirtFS nodes in this session. This could be all
	 * removed, unlinked VirtFS nodes on the host.
	 */
	VIRTFS_LOCK(vses);
	STAILQ_FOREACH_SAFE(p, &vses->virt_node_list, virtfs_node_next, tmp) {

		virtfs_cleanup(p);
	}
	VIRTFS_UNLOCK(vses);
	virtfs_complete_close(mp);
	/* Clean up the clnt structure. */
	p9_client_destroy(vses->clnt);
	VIRTFS_LOCK_DESTROY(vses);
	p9_debug(SUBR, " Clean close session .\n");
}

/*
 * Remove all the fids of a particular type from a VirtFS node
 * as well as destroy/clunk them.
 */
void
virtfs_fid_remove_all(struct virtfs_node *np)
{
	struct p9_fid *fid, *tfid;

	STAILQ_FOREACH_SAFE(fid, &np->vfid_list, fid_next, tfid) {
		STAILQ_REMOVE(&np->vfid_list, fid, p9_fid, fid_next);
		p9_client_clunk(fid);
	}

	STAILQ_FOREACH_SAFE(fid, &np->vofid_list, fid_next, tfid) {
		STAILQ_REMOVE(&np->vofid_list, fid, p9_fid, fid_next);
		p9_client_clunk(fid);
	}
}


/* Remove a fid from its corresponding fid list */
void
virtfs_fid_remove(struct virtfs_node *np, struct p9_fid *fid, int fid_type)
{

	switch (fid_type) {
	case VFID:
		VIRTFS_VFID_LOCK(np);
		STAILQ_REMOVE(&np->vfid_list, fid, p9_fid, fid_next);
		VIRTFS_VFID_UNLOCK(np);
		break;
	case VOFID:
		VIRTFS_VOFID_LOCK(np);
		STAILQ_REMOVE(&np->vofid_list, fid, p9_fid, fid_next);
		VIRTFS_VOFID_UNLOCK(np);
		break;
	}
}

/* Add a fid to the corresponding fid list */
void
virtfs_fid_add(struct virtfs_node *np, struct p9_fid *fid, int fid_type)
{

	switch (fid_type) {
	case VFID:
		VIRTFS_VFID_LOCK(np);
		STAILQ_INSERT_TAIL(&np->vfid_list, fid, fid_next);
		VIRTFS_VFID_UNLOCK(np);
		break;
	case VOFID:
		VIRTFS_VOFID_LOCK(np);
		STAILQ_INSERT_TAIL(&np->vofid_list, fid, fid_next);
		VIRTFS_VOFID_UNLOCK(np);
		break;
	}
}

/* Build the path from root to current directory */
static int
virtfs_get_full_path(struct virtfs_node *np, char ***names)
{
	int i, n;
	struct virtfs_node *node;
	char **wnames;

	n = 0;
	for (node = np ; (node != NULL) && !IS_ROOT(node) ; node = node->parent)
		n++;

	if (node == NULL)
		return 0;

	wnames = malloc(n * sizeof(char *), M_TEMP, M_ZERO|M_WAITOK);

	for (i = n-1, node = np; i >= 0 ; i--, node = node->parent)
		wnames[i] = node->inode.i_name;

	*names = wnames;
	return n;
}

/*
 * Retrieve fid structure corresponding to a particular
 * uid and fid type for a VirtFS node
 */
struct p9_fid *
virtfs_get_fid_from_uid(struct virtfs_node *np, uid_t uid, int fid_type)
{
	struct p9_fid *fid;

	switch (fid_type) {
	case VFID:
		VIRTFS_VFID_LOCK(np);
		STAILQ_FOREACH(fid, &np->vfid_list, fid_next) {
			if (fid->uid == uid) {
				VIRTFS_VFID_UNLOCK(np);
				return fid;
			}
		}
		VIRTFS_VFID_UNLOCK(np);
		break;
	case VOFID:
		VIRTFS_VOFID_LOCK(np);
		STAILQ_FOREACH(fid, &np->vofid_list, fid_next) {
			if (fid->uid == uid) {
				VIRTFS_VOFID_UNLOCK(np);
				return fid;
			}
		}
		VIRTFS_VOFID_UNLOCK(np);
		break;
	}

	return NULL;
}

/*
 * Function returns the fid sturcture for a file corresponding to current user id.
 * First it searches in the fid list of the corresponding VirtFS node.
 * New fid will be created if not already present and added in the corresponding
 * fid list in the VirtFS node.
 * If the user is not already attached then this will attach the user first
 * and then create a new fid for this particular file by doing dir walk.
 */
struct p9_fid *
virtfs_get_fid(struct p9_client *clnt, struct virtfs_node *np, int fid_type,
    int *error)
{
	uid_t uid;
	struct thread *td;
	struct p9_fid *fid, *oldfid;
	struct virtfs_node *root;
	struct virtfs_session *vses;
	int i, l, clone;
	char **wnames = NULL;
	uint16_t nwnames;

	td = curthread;
	oldfid = NULL;
	vses = np->virtfs_ses;

	if (vses->flags & P9_ACCESS_ANY)
		uid = vses->uid;
	else
		uid = td->td_ucred->cr_uid;

	/*
	 * Search for the fid in corresponding fid list.
	 * We should return NULL for VOFID if it is not present in the list.
	 * Because VOFID should have been created during the file open.
	 * If VFID is not present in the list then we should create one.
	 */
	fid = virtfs_get_fid_from_uid(np, uid, fid_type);
	if (fid != NULL || fid_type == VOFID)
		return fid;

	/* Check root if the user is attached */
	root = &np->virtfs_ses->rnp;
	fid = virtfs_get_fid_from_uid(root, uid, fid_type);
	if(fid == NULL) {
		/* Attach the user */
		fid = p9_client_attach(clnt, NULL, NULL, uid,
		    vses->aname, error);
		if (*error != 0)
			return NULL;
		virtfs_fid_add(root, fid, fid_type);
	}

	/* If we are looking for root then return it */
	if (IS_ROOT(np))
		return fid;

	/* If file is deleted, nothing to do */
	if ((np->flags & VIRTFS_NODE_DELETED) != 0) {
		*error = ENOENT;
		return NULL;
	}

	/* Get full path from root to virtfs node */
	nwnames = virtfs_get_full_path(np, &wnames);

	/*
	 * Could not get full path.
	 * If virtfs node is not deleted, parent should exist.
	 */
	KASSERT(nwnames != 0, ("%s: Directory of %s doesn't exist", __func__, np->inode.i_name));

	clone = 1;
	i = 0;
	while (i < nwnames) {
		l = MIN(nwnames - i, P9_MAXWELEM);

		fid = p9_client_walk(fid, l, wnames, clone, error);
		if (*error != 0) {
			if (oldfid)
				p9_client_clunk(oldfid);
			fid = NULL;
			goto bail_out;
		}
		oldfid = fid;
		clone = 0;
		i += l ;
	}
	virtfs_fid_add(np, fid, fid_type);
bail_out:
	free(wnames, M_TEMP);
	return fid;
}
