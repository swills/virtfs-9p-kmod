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

#include <sys/param.h>
#include <sys/queue.h>
#include <vm/uma.h>
#include <sys/fcntl.h>
#include <sys/param.h>
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
#include <sys/sysctl.h>
#include <dev/virtio/virtio_fs_client.h>
#include <dev/virtio/virtio_fs_protocol.h>
#include <dev/virtio/virtio_fs_9p.h>
#include "transport.h"

#define QEMU_HEADER 7
#define VIRTFS_MAX_FID_CNT (1024 * 1024 * 1024)
#define VIRTFS_ROOT_FID_NO 2
#define VIRTFS_MIN_TAG 1
#define VIRTFS_MAX_TAG 65535
#define WSTAT_SIZE 47
#define WSTAT_EXTENSION_SIZE 14

static MALLOC_DEFINE(M_P9CLNT, "p9_client", "P9 Client structure for virfs");
static uma_zone_t virtfs_fid_zone;
static uma_zone_t virtfs_req_zone;
static uma_zone_t virtfs_buf_zone;
int p9_debug_level = 0;
SYSCTL_INT(_vfs, OID_AUTO, p9_debug_level, CTLFLAG_RW,
    &p9_debug_level, 0, "Debug prints enabling switch for virtfs");

static struct p9_req_t *p9_get_request(void);
static struct p9_req_t *p9_client_request(
    struct p9_client *c, int8_t type, int *err, const char *fmt, ...);

inline int
p9_is_proto_dotl(struct p9_client *clnt)
{

	return (clnt->proto_version == p9_proto_2000L);
}

inline int
p9_is_proto_dotu(struct p9_client *clnt)
{

	return (clnt->proto_version == p9_proto_2000u);
}

static int
p9_parse_opts(struct mount  *mp, struct p9_client *clnt)
{
	char *trans;
	int error = 0;

	/* These are defaults for now */
	clnt->proto_version = p9_proto_2000L;
	clnt->msize = 8192;

	trans = vfs_getopts(mp->mnt_optnew, "trans", &error);
	if (error != 0)
		return (error);

	p9_debug(TRANS, "Attaching to the %s transport\n", trans);
	/* Get the default trans callback */
	clnt->trans_mod = p9_get_default_trans();

	return (error);
}

static struct p9_buffer *
p9_buffer_alloc(int alloc_msize)
{
	struct p9_buffer *fc = NULL;

	fc = uma_zalloc(virtfs_buf_zone, M_WAITOK | M_ZERO);
	fc->capacity = alloc_msize;
	fc->offset = 0;
	fc->size = 0;
	fc->sdata = (char *) fc + sizeof(struct p9_buffer);

	return (fc);
}

static void
p9_buffer_free(struct p9_buffer **buf)
{

	/* Free the sdata buffers first, then the whole structure*/
	uma_zfree(virtfs_buf_zone, *buf);
	*buf = NULL;
}

static void
p9_free_req(struct p9_req_t *req)
{

	if (req->tc != NULL)
		p9_buffer_free(&req->tc);

	if (req->rc != NULL)
		p9_buffer_free(&req->rc);

	req->tc = NULL;
	req->rc = NULL;
	uma_zfree(virtfs_req_zone, req);
}

static struct p9_req_t *
p9_get_request(void)
{
	struct p9_req_t *req = NULL;
	int alloc_msize = VIRTFS_MTU;

	req = uma_zalloc(virtfs_req_zone, M_WAITOK | M_ZERO);
	req->tc = p9_buffer_alloc(alloc_msize);
	req->rc = p9_buffer_alloc(alloc_msize);

	return (req);
}

static int
p9_parse_receive(struct p9_buffer *buf, struct p9_client *clnt)
{
	int8_t type;
	int16_t tag;
	int32_t size;
	int err;

	buf->offset = 0;

	/* This value is set by QEMU for the header.*/
	if (buf->size == 0)
		buf->size = QEMU_HEADER;

	/* This is the initial header. Parse size, type, and tag .*/
	err = p9_buf_readf(buf, 0, "dbw", &size, &type, &tag);
	if (err != 0)
		goto out;

	buf->size = size;
	buf->id = type;
	buf->tag = tag;
	p9_tag_destroy(clnt, tag);
	p9_debug(TRANS, "size=%d type: %d tag: %d\n", buf->size, buf->id, buf->tag);
out:
	return (err);
}

static int
p9_client_check_return(struct p9_client *c, struct p9_req_t *req)
{
	int err = 0;
	int ecode = 0;
	char *ename;

	/* Check what we have in the receive bufer .*/
	err = p9_parse_receive(req->rc, c);

	if (err != 0) {
		p9_debug(ERROR, "couldn't parse receive buffer %d\n", err);
		return (err);
	}
	/*
	 * No error, We are done with the preprocessing. Return to the caller
	 * and process the actual data.
	 */
	if (req->rc->id != P9PROTO_RERROR)
		return (0);

	/*
	 * Interpreting the error is done in different ways for Linux and Unix version
	 * Make sure you interpret it right.
	 */
	err = p9_buf_readf(req->rc, c->proto_version, "s?d", &ename, &ecode);

	if (err != 0)
		goto err_out;

	/* if there was an ecode error make this the err now */
	err = ecode;
	/*
	 * Note this is still not completely an error as, lookups for files not present
	 * can hit this and return. Hence its made a debug print.
	 */
	if (err != 0) {
		p9_debug(TRANS, "<<< RERROR (%d) %s\n", err, ename);
	}

	free(ename, M_TEMP);

	return (err);
err_out:
	p9_debug(ERROR, "couldn't parse error%d\n", err);

	return (err);
}

/* State machine changing helpers */
void p9_client_disconnect(struct p9_client *clnt)
{
	p9_debug(TRANS, "clnt %p\n", clnt);
	clnt->trans_status = VIRTFS_DISCONNECT;
}

void p9_client_begin_disconnect(struct p9_client *clnt)
{
	p9_debug(TRANS, "clnt %p\n", clnt);
	clnt->trans_status = VIRTFS_BEGIN_DISCONNECT;
}

static struct p9_req_t *
p9_client_prepare_req(struct p9_client *c, int8_t type,
    int req_size, int *err, const char *fmt, __va_list ap)
{
	struct p9_req_t *req = NULL;
	int error = 0;

	p9_debug(TRANS, "client %p op %d\n", c, type);

	/*
	 * Before we start with the request, check if its possible to finish this request.
	 * We are allowed to submit the request only if there are no close sessions happening
	 * or else there can be race. If the status is Disconnected, we stop any requests
	 * coming in after that.
	 */
	if (c->trans_status == VIRTFS_DISCONNECT) {
		error = EIO;
		return NULL;
	}

	/* Allow only cleanup clunk messages once we are starting to teardown.*/
	if ((c->trans_status == VIRTFS_BEGIN_DISCONNECT) && (type != P9PROTO_TCLUNK)) {
		error = EIO;
		return NULL;
	}

	req = p9_get_request();
	if (req == NULL) {
		p9_debug(ERROR, "request allocation failed.\n");
		error = ENOMEM;
		return NULL;
	}
	/* Marshall the data according to QEMU standards */
	error = p9_buf_prepare(req->tc, type, c);
	if (error != 0) {
		p9_debug(ERROR, "Buf_prepare failed prepare_req %d\n", error);
		goto reterr;
	}
	error = p9_buf_vwritef(req->tc, c->proto_version, fmt, ap);
	if (error != 0) {
		p9_debug(ERROR, "buf_vwrite failed in prepare_req %d \n", error);
		goto reterr;
	}
	error = p9_buf_finalize(c, req->tc);

	if (error != 0) {
		p9_debug(ERROR, "buf_finalize failed in prepare_req %d \n", error);
		goto reterr;
	}
	*err = error;

	return (req);
reterr:
	if (req)
		p9_free_req(req);
	*err = error;

	return NULL;
}

static struct p9_req_t *
p9_client_request(struct p9_client *c, int8_t type, int *err, const char *fmt, ...)
{
	va_list ap;
	struct p9_req_t *req = NULL;

	va_start(ap, fmt);
	req = p9_client_prepare_req(c, type, c->msize, err, fmt, ap);
	va_end(ap);

	if (req == NULL)
		return NULL;
	/*
	 * We have detected an error in client_prepare_req so no point in continuing further. Return NULL
	 * to the caller but we will analyze the error code in err wherever necessary.
	 */
	if (*err != 0)
		return NULL;

	/* Call into the transport for submission. */
	*err = c->trans_mod->request(c, req);

	if (*err != 0) {
		p9_debug(ERROR, "request submission failed \n");
		goto error;
	}
	/*
	 * Before we return, pre process the header and the rc buffer before calling
	 * into the protocol infra to analyze the data in rc.
	 */
	*err = p9_client_check_return(c, req);

	if (*err != 0)
		goto error;

	if (*err == 0)
		return req;
error:
	if (req != NULL)
		p9_free_req(req);

	return NULL;
}

uint16_t
p9_tag_create(struct p9_client *clnt)
{
        int tag;
        p9_debug(TRANS, "clnt %p\n", clnt);

        tag = alloc_unr(clnt->tagpool);
        /* Alloc_unr returning -1 is an error for no units left */
        if (tag == -1) {
                return P9_NOTAG;
        }
        return (tag);
}

void
p9_tag_destroy(struct p9_client *clnt, uint16_t tag)
{
        p9_debug(TRANS, "tag %d\n", tag);

        /* Release to the pool */
        free_unr(clnt->tagpool, tag);
}

struct p9_fid *
p9_fid_create(struct p9_client *clnt)
{
	struct p9_fid *fid;

	p9_debug(TRANS, "clnt %p\n", clnt);

	fid = uma_zalloc(virtfs_fid_zone, M_WAITOK | M_ZERO);
	fid->fid = alloc_unr(clnt->fidpool);
	/* Alloc_unr returning -1 is an error for no units left */
	if (fid->fid == -1) {
		uma_zfree(virtfs_fid_zone, fid);
		return NULL;
	}
	memset(&fid->qid, 0, sizeof(struct p9_qid));
	fid->mode = -1;
	fid->uid = -1;
	fid->clnt = clnt;

	return (fid);
}

void
p9_fid_destroy(struct p9_fid *fid)
{
	struct p9_client *clnt;

	p9_debug(TRANS, "fid %d\n", fid->fid);

	clnt = fid->clnt;
	/* Release to the pool */
	free_unr(clnt->fidpool, fid->fid);
	uma_zfree(virtfs_fid_zone, fid);
}

int
p9_client_version(struct p9_client *c)
{
	int err = 0;
	struct p9_req_t *req;
	char *version;
	int msize;

	p9_debug(TRANS, "TVERSION msize %d protocol %d\n", c->msize, c->proto_version);

	switch (c->proto_version) {
	case p9_proto_2000L:
		req = p9_client_request(c, P9PROTO_TVERSION, &err, "ds",
		    c->msize, "9P2000.L");
		break;
	case p9_proto_2000u:
		req = p9_client_request(c, P9PROTO_TVERSION, &err, "ds",
		    c->msize, "9P2000.u");
		break;
	case p9_proto_legacy:
		req = p9_client_request(c, P9PROTO_TVERSION, &err, "ds",
		    c->msize, "9P2000");
		break;
	default:
		return (EINVAL);
	}

	/*  Always return the relevant error code */
	if (req == NULL)
		return (err);

	err = p9_buf_readf(req->rc, c->proto_version, "ds", &msize, &version);
	if (err != 0) {
		p9_debug(ERROR, "version error %d\n", err);
		goto error;
	}

	p9_debug(TRANS, "RVERSION msize %d %s\n", msize, version);

	if (!strncmp(version, "9P2000.L", 8))
		c->proto_version = p9_proto_2000L;
	else if (!strncmp(version, "9P2000.u", 8))
		c->proto_version = p9_proto_2000u;
	else if (!strncmp(version, "9P2000", 6))
		c->proto_version = p9_proto_legacy;
	else {
		err = ENOMEM;
		goto error;
	}

	/* limit the msize .*/
	if (msize < c->msize)
		c->msize = msize;

error:
	p9_free_req(req);

	return (err);
}

/*
 * Initialize zones for different things. This is called from Init module
 * so that we just have them initalized once.
 */
void
p9_init_zones(void)
{

	/* Create the request and the fid zones */
	virtfs_fid_zone = uma_zcreate("virtfs fid zone",
	    sizeof(struct p9_fid), NULL, NULL, NULL, NULL, 0, 0);

	/* Create the request and the fid zones */
	virtfs_req_zone = uma_zcreate("virtfs req zone",
	    sizeof(struct p9_req_t), NULL, NULL, NULL, NULL, 0, 0);

	/* Create the buffer zone */
	virtfs_buf_zone = uma_zcreate("virtfs buf zone",
	    sizeof(struct p9_buffer) + VIRTFS_MTU, NULL, NULL,
	    NULL, NULL, 0, 0);
}

void
p9_destroy_zones(void)
{

	uma_zdestroy(virtfs_fid_zone);
	uma_zdestroy(virtfs_req_zone);
	uma_zdestroy(virtfs_buf_zone);
}

/* Return the client to the session in the FS to hold it */
struct p9_client *
p9_client_create(struct mount *mp, int *error)
{
	int err = 0;
	struct p9_client *clnt;

	clnt = malloc(sizeof(struct p9_client), M_P9CLNT, M_WAITOK | M_ZERO);

	/* Parse should have set trans_mod */
	err = p9_parse_opts(mp, clnt);
	if (err != 0)
		goto bail_out;

	if (clnt->trans_mod == NULL) {
		err = EINVAL;
		p9_debug(ERROR, "No transport defined or default transport\n");
		goto bail_out;
	}

	/* Note: All the structures from here are protected by the lock clnt-spin */
	clnt->fidpool = new_unrhdr(VIRTFS_ROOT_FID_NO, VIRTFS_MAX_FID_CNT, NULL);
	if (clnt->fidpool == NULL) {
		err = ENOMEM;
		p9_debug(ERROR, "Coudlnt initilize fid pool\n");
		goto bail_out;
	}

	clnt->tagpool = new_unrhdr(VIRTFS_MIN_TAG, VIRTFS_MAX_TAG, NULL);
        if (clnt->tagpool == NULL) {
                err = ENOMEM;
                p9_debug(ERROR, "Couldnt initialize tag pool\n");
                goto bail_out;
        }

	p9_debug(TRANS, "clnt %p trans %p msize %d protocol %d\n",
	    clnt, clnt->trans_mod, clnt->msize, clnt->proto_version);

	err = clnt->trans_mod->create(clnt);
	if (err != 0) {
		p9_debug(ERROR, "transport create failed .%d \n",err);
		goto bail_out;
	}

	err = p9_client_version(clnt);
	if (err != 0)
		goto bail_out;

	p9_debug(TRANS, "Client creation success .\n");
	*error = 0;

	return (clnt);

bail_out:
	if (clnt)
		free(clnt, M_P9CLNT);

	*error = err;

	return NULL;
}

void
p9_client_destroy(struct p9_client *clnt)
{

	p9_debug(TRANS, "clnt %s %p\n", __func__, clnt);

	p9_put_trans(clnt->trans_mod);

	if (clnt->fidpool != NULL)
		delete_unrhdr(clnt->fidpool);

	if (clnt->tagpool != NULL)
		delete_unrhdr(clnt->tagpool);
	free(clnt, M_P9CLNT);
}

/*
 * Called from mount. fid returned is created for the root inode.
 * the other instances already have the afid.
 */
struct p9_fid *
p9_client_attach(struct p9_client *clnt, int *error)
{
	int err = 0;
	struct p9_req_t *req = NULL;
	struct p9_fid *fid = NULL;
	struct p9_qid qid;

	p9_debug(TRANS, "TATTACH \n");
	fid = p9_fid_create(clnt);

	if (fid == NULL) {
		err = ENOMEM;
		fid = NULL;
		goto error;
	}
	fid->uid = -1;

	req = p9_client_request(clnt, P9PROTO_TATTACH, &err, "ddssd", fid->fid,
	    P9PROTO_NOFID, "nobody", "", fid->uid);

	if (req == NULL) {
		goto error;
	}

	err = p9_buf_readf(req->rc, clnt->proto_version, "Q", &qid);

	if (err != 0) {
		p9_debug(ERROR, "buf_readf failed in client_attach %d \n", err);
		goto error;
	}

	p9_debug(TRANS, "RATTACH qid %x.%llx.%x\n",
	    qid.type, (unsigned long long)qid.path, qid.version);

	memmove(&fid->qid, &qid, sizeof(struct p9_qid));
	p9_free_req(req);

	*error = err;

	return (fid);

error:
	if (req != NULL)
		p9_free_req(req);
	if (fid != NULL)
		p9_fid_destroy(fid);
	*error = err;

	return NULL;
}

/*
 * client_remove removes the fid allocated by the server. This is usually called
 * while removing files.
 */
int
p9_client_remove(struct p9_fid *fid)
{
	int err;
	struct p9_client *clnt;
	struct p9_req_t *req;

	p9_debug(TRANS, "TREMOVE fid %d\n", fid->fid);
	err = 0;
	clnt = fid->clnt;

	req = p9_client_request(clnt, P9PROTO_TREMOVE, &err, "d", fid->fid);
	if (req == NULL)
		goto error;

	p9_debug(TRANS, "RREMOVE fid %d\n", fid->fid);
	p9_free_req(req);
error:
	p9_fid_destroy(fid);

	return (err);
}

/*
 * Any allocated fid on the server needs a clunk to be destroyed. Also
 * When an extra fid has been created on the qemu and we found errors, we are going
 * to clunk the fid again and free the fid to return ENOENT (e.g. from lookup to reflect
 * that)
 */
int
p9_client_clunk(struct p9_fid *fid)
{
	int err = 0;
	struct p9_client *clnt;
	struct p9_req_t *req;

	if (fid == NULL) {
		p9_debug(ERROR, "clunk with NULL fid is bad\n");
		return (0);
	}

	p9_debug(TRANS, "TCLUNK fid %d \n", fid->fid);

	clnt = fid->clnt;
	req = p9_client_request(clnt, P9PROTO_TCLUNK, &err, "d", fid->fid);
	if (req == NULL)
		goto error;

	p9_debug(TRANS, "RCLUNK fid %d\n", fid->fid);
	p9_free_req(req);
error:
	p9_fid_destroy(fid);

	return (err);
}

/*
 * Client_walk is for searching any component name in a directory.
 * This is usually called on lookups. Also when we need a new open fid
 * as 9p needs to have an open fid for every file to fileops, we call this
 * validate the component of the file and return the newfid(openfid) created.
 */
struct p9_fid *
p9_client_walk(struct p9_fid *oldfid, char  *wname,
    size_t wnamelen, int clone, int *error)
{
	int err;
	struct p9_client *clnt;
	struct p9_fid *fid;
	struct p9_qid *wqids;
	struct p9_req_t *req;
	uint16_t nwqids, count;
        uint16_t nwname;

        nwname = (wname == NULL) ? 0:1;
	err = 0;
	wqids = NULL;
	clnt = oldfid->clnt;

	/*
	 *  Before, we go and create fid, make sure we are not tearing
	 *  down. Only then we create.
	 */
	/* Allow only cleanup clunk messages once we are starting to teardown.*/
	if (clnt->trans_status != VIRTFS_CONNECT) {
		*error = EIO;
		return NULL;
	}

	if (clone) {

		fid = p9_fid_create(clnt);
		if (fid == NULL) {
			err = ENOMEM;
			goto error;
		}

		fid->uid = oldfid->uid;
	} else
		fid = oldfid;

	p9_debug(TRANS, "TWALK fids %d,%d wnamelen %ud wname %s\n",
	    oldfid->fid, fid->fid, wnamelen, wname ? wname : NULL);

	/*
	 * The newfid is for the component in search. We are preallocating as qemu
	 * on the other side allocates or returns a fid if it sees a match
	 */
	req = p9_client_request(clnt, P9PROTO_TWALK, &err, "ddT", oldfid->fid, fid->fid,
	    wname, wnamelen);
	if (req == NULL)
		goto error;

	err = p9_buf_readf(req->rc, clnt->proto_version, "R", &nwqids, &wqids);
	if (err != 0) {
		p9_free_req(req);
		goto clunk_fid;
	}
	p9_free_req(req);

	p9_debug(TRANS, "RWALK nwqid %d:\n", nwqids);

	if (nwqids != nwname) {
		err = ENOENT;
		goto clunk_fid;
	}

	for (count = 0; count < nwqids; count++)
		p9_debug(TRANS, "[%d] %x.%llx.%x\n", count, wqids[count].type,
		    (unsigned long long)wqids[count].path, wqids[count].version);

	if (nwname)
		memmove(&fid->qid, &wqids[nwqids - 1], sizeof(struct p9_qid));
	else
		fid->qid = oldfid->qid;

	free(wqids, M_TEMP);
	*error = err;

	return (fid);

clunk_fid:
	free(wqids, M_TEMP);
	p9_client_clunk(fid);
	fid = NULL;

error:
	if (fid && fid != oldfid)
		p9_fid_destroy(fid);

	*error = err;

	return NULL;
}

/* Called for opening a file. Fid of the file to open with mode.*/
int
p9_client_open(struct p9_fid *fid, int mode)
{
	int err = 0;
	struct p9_client *clnt;
	struct p9_req_t *req;
	int mtu = 0;

	clnt = fid->clnt;
	p9_debug(TRANS, "%s fid %d mode %d\n", p9_is_proto_dotl(clnt) ? "TLOPEN" : "TOPEN", fid->fid, mode);

	if (fid->mode != -1)
		return (EINVAL);

	if (p9_is_proto_dotl(clnt))
		req = p9_client_request(clnt, P9PROTO_TLOPEN, &err, "dd", fid->fid, mode);
	else
		req = p9_client_request(clnt, P9PROTO_TOPEN, &err, "db", fid->fid, mode);

	if (req == NULL)
		goto out;

	err = p9_buf_readf(req->rc, clnt->proto_version, "Qd", &fid->qid, &mtu);
	if (err != 0)
		goto out;

	p9_debug(TRANS, " %s qid %x.%llx.%x mtu %x\n", p9_is_proto_dotl(clnt) ? "RLOPEN" : "ROPEN",
	    (fid->qid).type, (unsigned long long)(fid->qid).path, (fid->qid).version, mtu);

	fid->mode = mode;
	fid->mtu = mtu;
out:
	if (req != NULL)
		p9_free_req(req);

	return (err);
}

/* client_Stat gets all the stats from a file denoted by its fid. */
int
p9_client_stat(struct p9_fid *fid, struct p9_wstat **stat)
{
	int err = 0;
	struct p9_client *clnt;
	struct p9_req_t *req = NULL;
	uint16_t ignored;

	p9_debug(TRANS, "TSTAT fid %d\n", fid->fid);

	clnt = fid->clnt;
	req = p9_client_request(clnt, P9PROTO_TSTAT, &err, "d", fid->fid);
	if (req == NULL) {
		p9_debug(ERROR, "Request couldnt be allocated in client_stat %d\n",err);
		goto error;
	}

	err = p9_buf_readf(req->rc, clnt->proto_version, "wS", &ignored, (*stat));
	if (err != 0) {
		p9_debug(ERROR, "buf_readf failed in client_stat %d\n", err);
		goto error;
	}

	p9_free_req(req);

	return (err);

error:
	if (req != NULL)
		p9_free_req(req);

	return (err);
}

/*
 * Compute the stat size structure to write to the server. Since there are
 * strings in it can be variable. Hence it has to be calculated everytime
 */
static int
p9_client_statsize(struct p9_wstat *wst, int proto_version)
{
	int ret = WSTAT_SIZE;

	/* Adding the strlen + 1(NULL) for all strings */
	if (wst->name)
		ret += strlen(wst->name) + 1;
	if (wst->uid)
		ret += strlen(wst->uid) + 1;
	if (wst->gid)
		ret += strlen(wst->gid) + 1;
	if (wst->muid)
		ret += strlen(wst->muid) + 1;

	ret += WSTAT_EXTENSION_SIZE;

	if (wst->extension) {
		ret += strlen(wst->extension) + 1;
	}

	return (ret);
}

/*
 * Write wstat. Called  by setattr. wstat structure is written
 * for fid file
 */
int
p9_client_wstat(struct p9_fid *fid, struct p9_wstat *wst)
{
	int err = 0;
	struct p9_req_t *req;
	struct p9_client *clnt;

	p9_debug(TRANS, "TWSTAT fid %d  %p%d\n", fid->fid, wst);

	clnt = fid->clnt;
	/*Computing the size as we have variable sized strings */
	wst->size = p9_client_statsize(wst, clnt->proto_version);
	/* Any client_request error is converted to req == NULL error*/
	req = p9_client_request(clnt, P9PROTO_TWSTAT, &err, "dwS", fid->fid, wst->size+2, wst);
	if (req == NULL) {
		p9_debug(ERROR, "Couldn't allocate request in client_wstat %d\n",err);
		goto error;
	}

	p9_free_req(req);
error:
	return (err);
}

int
p9_client_readdir(struct p9_fid *fid, char *data, uint64_t offset, uint32_t count)
{
	int err = 0;
	uint32_t rsize;
	struct p9_client *clnt;
	struct p9_req_t *req = NULL;
	char *dataptr;

	p9_debug(TRANS, "TREADDIR fid %d offset %llu count %d\n",
	    fid->fid, (unsigned long long) offset, count);

	rsize = fid->mtu;
	clnt = fid->clnt;

	if (!rsize || rsize > clnt->msize)
		rsize = clnt->msize;

	if (count < rsize)
		rsize = count;

	req = p9_client_request(clnt, P9PROTO_TREADDIR, &err, "dqd", fid->fid,
	    offset, rsize);

	if (req == NULL) {
		p9_debug(ERROR, "Couldn't allocate request in client_readdir \n");
		goto error;
	}

	err = p9_buf_readf(req->rc, clnt->proto_version, "D", &count, &dataptr);
	if (err != 0) {
		p9_debug(ERROR, "buf_readf error in client_readdir \n");
		goto error;
	}

	p9_debug(TRANS, "RREADDIR count %u\n", count);

	/* Copy back the data into the input buffer. */
	memmove(data, dataptr, count);
	p9_free_req(req);

	return (count);
error:
	if (req != NULL)
		p9_free_req(req);

	return (-err);
}

/*
 * client_read reads count bytes from offset for the file fid into the character buffer
 * data. This buffer is handed over to VIRTFS to process into user buffers.
 * Note the this function typically returns the number of bytes read so in case of an error
 * we return -error so that we can distinguish between error codes and bytes.
 */
int
p9_client_read(struct p9_fid *fid, uint64_t offset, uint32_t count, char *data)
{
	struct p9_client *clnt = fid->clnt;
	struct p9_req_t *req = NULL;
	char *dataptr;
	int err = 0;
	int rsize;

	p9_debug(TRANS, "TREAD fid %d offset %llu %u\n",
	    fid->fid, (unsigned long long) offset, count);

	rsize = fid->mtu;
	if (!rsize || rsize > clnt->msize)
		rsize = clnt->msize;

	if (count < rsize)
		rsize = count;

	/* At this stage, we only have 8K buffers so only transfer */
	req = p9_client_request(clnt, P9PROTO_TREAD, &err, "dqd", fid->fid, offset,
	    rsize);
	if (req == NULL) {
		p9_debug(ERROR, "Coudlnt allocate request in client_read \n");
		goto error;
	}

	err = p9_buf_readf(req->rc, clnt->proto_version, "D", &count, &dataptr);
	if (err != 0) {
		p9_debug(ERROR, "p9_buf_readf error in client_read \n");
		goto error;
	}

	if (rsize < count) {
		p9_debug(TRANS, "RREAD count (%d > %d)\n", count, rsize);
		count = rsize;
	}

	p9_debug(TRANS, "RREAD count %d\n", count);

	if (count == 0) {
		err = -EIO;
		p9_debug(ERROR, "EIO error in client_read \n");
		goto error;
	}

	/* Copy back the data into the input buffer. */
	memmove(data, dataptr, count);

	p9_free_req(req);
	req = NULL;

	return count;
error:

	if (req != NULL)
		p9_free_req(req);

	return (-err);
}

int
p9_client_write(struct p9_fid *fid, uint64_t offset, uint32_t count, char *data)
{
	struct p9_client *clnt = fid->clnt;
	struct p9_req_t *req = NULL;
	int ret = 0;
	int err = 0;
	int rsize;

	p9_debug(TRANS, " TWRITE fid %d offset %llu  %u\n",
	    fid->fid, (unsigned long long) offset, count);

	rsize = fid->mtu;
	if (!rsize || rsize > clnt->msize)
		rsize = clnt->msize;

	/* Limit set by Qemu ,8168 */
	if (count > rsize) {
		count = rsize;
	}

	/* Doing the Data blob instead. If at all we add the zerocopy, we can change it
	 * to uio direct copy.*/
	req = p9_client_request(clnt, P9PROTO_TWRITE, &err, "dqD", fid->fid,
	    offset, count, data);
	if (req == NULL) {
		p9_debug(ERROR, "Coudlnt allocate request in client_write \n");
		goto error;
	}

	err = p9_buf_readf(req->rc, clnt->proto_version, "d", &ret);
	if (err) {
		p9_debug(ERROR, "p9_buf_readf error in client_write \n");
		goto error;
	}

	p9_debug(TRANS, " RWRITE count %d\n", ret);

	if (count < ret) {
		p9_debug(TRANS, "RWRITE count BUG(%d > %d)\n", count, ret);
		ret = count;
	}

	if (count == 0) {
		err = -EIO;
		p9_debug(ERROR, "EIO error in client_write \n");
		goto error;
	}

	p9_free_req(req);

	return (ret);
error:
	if (req != NULL)
		p9_free_req(req);

	return (-err);
}

/*
 * file create function created under directory fid, with name, permissions,
 * mode.
 */

int
p9_client_file_create(struct p9_fid *fid, char *name, uint32_t perm, int mode,
    char *extension)
{
	int err = 0;
	struct p9_client *clnt;
	struct p9_req_t *req;
	struct p9_qid qid;
	int mtu;

	p9_debug(TRANS, "TCREATE fid %d name %s perm %d mode %d\n",
	    fid->fid, name, perm, mode);

	clnt = fid->clnt;

	if (fid->mode != -1)
		return (EINVAL);

	req = p9_client_request(clnt, P9PROTO_TCREATE, &err, "dsdb?s", fid->fid, name, perm,
	    mode, extension);
	if (req == NULL)
		goto error;

	err = p9_buf_readf(req->rc, clnt->proto_version, "Qd", &qid, &mtu);

	if (err != 0)
		goto error;

	p9_debug(TRANS, "RCREATE qid %x.%llx.%x mtu %x\n", qid.type, qid.path, qid.version, mtu);
	fid->mode = mode;
	fid->mtu = mtu;

error:
	if (req != NULL)
		p9_free_req(req);

	return (err);
}

int
p9_client_statfs(struct p9_fid *fid, struct p9_statfs *stat)
{
	int err;
	struct p9_req_t *req;
	struct p9_client *clnt;

	err = 0;
	clnt = fid->clnt;

	p9_debug(TRANS, "TSTATFS fid %d\n", fid->fid);

	req = p9_client_request(clnt, P9PROTO_TSTATFS, &err, "d", fid->fid);
	if (req == NULL) {
		goto error;
	}

	err = p9_buf_readf(req->rc, clnt->proto_version, "ddqqqqqqd", &stat->type,
	    &stat->bsize, &stat->blocks, &stat->bfree, &stat->bavail,
	    &stat->files, &stat->ffree, &stat->fsid, &stat->namelen);

	if (err != 0) {
		p9_free_req(req);
		goto error;
	}

	p9_debug(TRANS, "STATFS fid %d type 0x%lx bsize %ld "
	    "blocks %lu bfree %lu bavail %lu files %lu ffree %lu "
	    "fsid %lu namelen %ld\n", fid->fid, (long unsigned int)stat->type,
	    (long int)stat->bsize, stat->blocks, stat->bfree, stat->bavail,
	    stat->files,  stat->ffree, stat->fsid, (long int)stat->namelen);

	p9_free_req(req);
error:
	return (err);
}
