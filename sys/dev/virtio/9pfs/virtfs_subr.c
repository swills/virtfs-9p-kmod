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
 * Plan9 filesystem (9P2000.u) subroutines.  This file is intended primarily
 * for Plan9-specific details.
 * This file consists of all the Non VFS Subroutines.
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

struct p9_fid *
virtfs_init_session(struct mount *mp, int *error)
{
	struct p9_fid *fid;
	struct virtfs_session *vses;
	struct virtfs_mount *virtmp;

	virtmp = mp->mnt_data;
	vses = &virtmp->virtfs_session;
	vses->uid = 0;

	/*
	* Create the client structure. Call into the driver to create
	* driver structures for the actual IO transfer.
	*/
	vses->clnt = p9_client_create(mp, error);

	if (vses->clnt == NULL) {
		p9_debug(ERROR, "problem initializing 9p client\n");
		goto fail;
	}
	/*
	 * Find the client version and cache the copy. We will use this copy
	 * throughout FS layer.
	 */
	if (p9_is_proto_dotl(vses->clnt))
		vses->flags |= VIRTFS_PROTO_2000L;
	else if (p9_is_proto_dotu(vses->clnt))
		vses->flags |= VIRTFS_PROTO_2000U;

	/* Attach with the backend host*/
	fid = p9_client_attach(vses->clnt, error);

	if (fid == NULL) {
		p9_debug(ERROR, "cannot attach\n");
		goto fail;
	}
	p9_debug(SUBR, "Attach successful fid :%p\n", fid);

	fid->uid = vses->uid;

	/* init the node list for the session */
	STAILQ_INIT(&vses->virt_node_list);
	VIRTFS_LOCK_INIT(vses);

	p9_debug(SUBR, "INIT session successful\n");

	return fid;
fail:
	if (vses->clnt)
		p9_client_destroy(vses->clnt);

	return NULL;
}

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
	struct virtfs_node *p;

	vmp = VFSTOP9(mp);
	vses = &vmp->virtfs_session;

	/*
	 * Cleanup the leftover virtfs_nodes in this session. This could be all
	 * removed, unlinked virtfs_nodes on the host.
	 */
	VIRTFS_LOCK(vses);
	STAILQ_FOREACH(p, &vses->virt_node_list, virtfs_node_next) {
		(void)p9_client_clunk(p->vfid);
		/* If we still have some open fids around, destroy them as well.*/
		if (p->vofid)
			(void)p9_client_clunk(p->vofid);
		virtfs_cleanup(p);
	}
	VIRTFS_UNLOCK(vses);
	virtfs_complete_close(mp);
	/* Clean up the clnt structure. */
	p9_client_destroy(vses->clnt);
	VIRTFS_LOCK_DESTROY(vses);
	p9_debug(SUBR, " Clean close session .\n");
}
