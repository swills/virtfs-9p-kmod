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
/*
 * The Virtio 9P transport driver. This file contains all functions related to
 * the virtqueue infrastructure which include creating the virtqueue, host
 * interactions, interrupts etc.
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/module.h>
#include <sys/sglist.h>
#include <sys/queue.h>
#include <sys/bus.h>
#include <sys/kthread.h>
#include <sys/condvar.h>
#include <sys/sysctl.h>

#include <machine/bus.h>

#include <dev/virtio/virtio_fs_client.h>
#include <dev/virtio/virtio_fs_protocol.h>
#include <dev/virtio/virtio_fs_9p.h>
#include <dev/virtio/virtio.h>
#include <dev/virtio/virtqueue.h>
#include <dev/virtio/virtio_ring.h>

#include "transport.h"
#include "virtio_9p_config.h"

#define VT9P_MTX(_sc) (&(_sc)->vt9p_mtx)
#define VT9P_LOCK(_sc) mtx_lock(VT9P_MTX(_sc))
#define VT9P_UNLOCK(_sc) mtx_unlock(VT9P_MTX(_sc))
#define VT9P_LOCK_INIT(_sc) mtx_init(VT9P_MTX(_sc), \
    "VIRTIO 9P CHAN lock", NULL, MTX_DEF)
#define VT9P_LOCK_DESTROY(_sc) mtx_destroy(VT9P_MTX(_sc))
#define MAX_SUPPORTED_SGS 20
static MALLOC_DEFINE(M_VIRTFS_MNTTAG, "virtfs_mount_tag", "VirtFS Mounttag");
struct vt9p_softc {
	device_t vt9p_dev;
	struct mtx vt9p_mtx;
	struct sglist *vt9p_sglist;
	struct cv submit_cv;
	struct p9_client *client;
	struct virtqueue *vt9p_vq;
	int max_nsegs;
	uint16_t mount_tag_len;
	char *mount_tag;
	STAILQ_ENTRY(vt9p_softc) chan_next;
};

/* Global channel list, Each channel will correspond to a mount point */
STAILQ_HEAD( ,vt9p_softc) global_chan_list;
struct mtx global_chan_list_mtx;

static struct virtio_feature_desc virtio_9p_feature_desc[] = {
	{ VIRTIO_9PNET_F_MOUNT_TAG,	"VIRTFS_MOUNT_TAG" },
	{ 0, NULL }
};

static void
global_chan_list_init(void)
{

	mtx_init(&global_chan_list_mtx, "GLOBAL CHAN LIST LOCK",
	    NULL, MTX_DEF);
	STAILQ_INIT(&global_chan_list);
}
SYSINIT(global_chan_list_init, SI_SUB_KLD, SI_ORDER_FIRST,
    global_chan_list_init, NULL);

/* We don't currently allow canceling of virtio requests */
static int
vt9p_cancel(struct p9_client *client, struct p9_req_t *req)
{

	return (1);
}

SYSCTL_NODE(_vfs, OID_AUTO, 9p, CTLFLAG_RW, 0, "9P File System Protocol");

/*
 * Maximum number of seconds vt9p_request thread sleep waiting for an
 * ack from the host, before exiting
 */
static unsigned int vt9p_ackmaxidle = 120;

SYSCTL_UINT(_vfs_9p, OID_AUTO, ackmaxidle, CTLFLAG_RW, &vt9p_ackmaxidle, 0,
    "Maximum time request thread waits for ack from host");

/*
 * Request handler. This is called for every request submitted to the host
 * It basically maps the tc/rc buffers to sg lists and submits the requests
 * into the virtqueue. Since we have implemented a synchronous version, the
 * submission thread sleeps until the ack in the interrupt wakes it up. Once
 * it wakes up, it returns back to the VirtFS layer. The rc buffer is then
 * processed and completed to its upper layers.
 */
static int
vt9p_request(struct p9_client *client, struct p9_req_t *req)
{
	int error;
	struct vt9p_softc *chan;
	struct p9_req_t *curreq;
	int readable, writable;
	struct sglist *sg;
	struct virtqueue *vq;

	chan = client->trans;
	sg = chan->vt9p_sglist;
	vq = chan->vt9p_vq;

	p9_debug(TRANS, "9P debug: virtio request\n");

	/* Grab the channel lock*/
	VT9P_LOCK(chan);
	sglist_reset(sg);
	/* Handle out VirtIO ring buffers */
	error = sglist_append(sg, req->tc->sdata, req->tc->size);
	if (error != 0) {
		p9_debug(ERROR, "sglist append failed\n");
		return (error);
	}
	readable = sg->sg_nseg;

	error = sglist_append(sg, req->rc->sdata, req->rc->capacity);
	if (error != 0) {
		p9_debug(ERROR, " sglist append failed\n");
		return (error);
	}
	writable = sg->sg_nseg - readable;

req_retry:
	error = virtqueue_enqueue(vq, req, sg, readable, writable);

	if (error != 0) {
		if (error == ENOSPC) {
			/*
			 * Condvar for the submit queue. Unlock the chan
			 * since wakeup needs one.
			 */
			cv_wait(&chan->submit_cv, VT9P_MTX(chan));
			p9_debug(TRANS, "Retry virtio request\n");
			goto req_retry;
		} else {
			p9_debug(ERROR, "virtio enuqueue failed \n");
			return (EIO);
		}
	}

	/* We have to notify */
	virtqueue_notify(vq);

	do {
		curreq = virtqueue_dequeue(vq, NULL);
		if (curreq == NULL) {
			/* Nothing to dequeue, sleep until we have something */
			if (msleep(chan, VT9P_MTX(chan), 0, "chan lock",
			    vt9p_ackmaxidle * hz)) {
				/*
				 * Waited for 120s. No response from host.
				 * Can't wait for ever..
				 */
				p9_debug(ERROR, "Timeout after waiting %u seconds"
				    "for an ack from host\n", vt9p_ackmaxidle);
				VT9P_UNLOCK(chan);
				return (EIO);
			}
		} else {
		        cv_signal(&chan->submit_cv);
			/* We dequeued something, update the reply tag */
			curreq->rc->tag = curreq->tc->tag;
		}
	} while (req->rc->tag == P9_NOTAG);

	VT9P_UNLOCK(chan);

	p9_debug(TRANS, "virtio request kicked\n");

	return (0);
}

/*
 * Completion of the request from the virtqueue. This interrupt handler is
 * setup at initialization and is called for every completing request. It
 * just wakes up the sleeping submission thread.
 */
static void
vt9p_intr_complete(void *xsc)
{
	struct vt9p_softc *chan;
	struct virtqueue *vq;

	chan = (struct vt9p_softc *)xsc;
	vq = chan->vt9p_vq;

	p9_debug(TRANS, "Completing interrupt \n");

	VT9P_LOCK(chan);
	virtqueue_enable_intr(vq);
	wakeup(chan);
	VT9P_UNLOCK(chan);
}

/*
 * Allocation of the virtqueue with interrupt complete routines.
 */
static int
vt9p_alloc_virtqueue(struct vt9p_softc *sc)
{
	struct vq_alloc_info vq_info;
	device_t dev;

	dev = sc->vt9p_dev;

	VQ_ALLOC_INFO_INIT(&vq_info, sc->max_nsegs,
	    vt9p_intr_complete, sc, &sc->vt9p_vq,
	    "%s request", device_get_nameunit(dev));

	return (virtio_alloc_virtqueues(dev, 0, 1, &vq_info));
}

/* Probe for existence of 9P virtio channels */
static int
vt9p_probe(device_t dev)
{

	/* If the virtio device type is a 9P device, then we claim and attach it */
	if (virtio_get_device_type(dev) != VIRTIO_ID_9P)
		return (ENXIO);
	device_set_desc(dev, "VirtIO 9P Transport");
	p9_debug(TRANS, "Probe successful .\n");

	return (BUS_PROBE_DEFAULT);
}

static void
vt9p_stop(struct vt9p_softc *sc)
{

	/* Device specific stops .*/
	virtqueue_disable_intr(sc->vt9p_vq);
	virtio_stop(sc->vt9p_dev);
}

/* Detach the 9P virtio PCI device */
static int
vt9p_detach(device_t dev)
{
	struct vt9p_softc *sc;

	sc = device_get_softc(dev);
	VT9P_LOCK(sc);
	vt9p_stop(sc);
	VT9P_UNLOCK(sc);

	if (sc->vt9p_sglist) {
		sglist_free(sc->vt9p_sglist);
		sc->vt9p_sglist = NULL;
	}
	if (sc->mount_tag) {
		free(sc->mount_tag, M_VIRTFS_MNTTAG);
		sc->mount_tag = NULL;
	}
	mtx_lock(&global_chan_list_mtx);
	STAILQ_REMOVE(&global_chan_list, sc, vt9p_softc, chan_next);
	mtx_unlock(&global_chan_list_mtx);

	VT9P_LOCK_DESTROY(sc);
	cv_destroy(&sc->submit_cv);

	return (0);
}

/* Attach the 9P virtio PCI device */
static int
vt9p_attach(device_t dev)
{
	struct sysctl_ctx_list *ctx;
	struct sysctl_oid *tree;
	struct vt9p_softc *chan;
	char *mount_tag;
	int error;
	uint16_t mount_tag_len;

	chan = device_get_softc(dev);
	chan->vt9p_dev = dev;

	/* Init the channel lock. */
	VT9P_LOCK_INIT(chan);
	/* Initialize the condition variable */
	cv_init(&chan->submit_cv, "Conditional variable for submit queue" );
	chan->max_nsegs = MAX_SUPPORTED_SGS;
	chan->vt9p_sglist = sglist_alloc(chan->max_nsegs, M_NOWAIT);

	/* Negotiate the features from the host */
	virtio_set_feature_desc(dev, virtio_9p_feature_desc);
	virtio_negotiate_features(dev, VIRTIO_9PNET_F_MOUNT_TAG);

	/*
	 * If mount tag feature is supported read the mount tag
	 * from device config
	 */
	if (virtio_with_feature(dev, VIRTIO_9PNET_F_MOUNT_TAG))
		mount_tag_len = virtio_read_dev_config_2(dev,
		    offsetof(struct virtio_9pnet_config, mount_tag_len));
	else {
		error = EINVAL;
		p9_debug(ERROR, "Mount tag feature not supported by host\n");
		goto out;
	}
	mount_tag = malloc(mount_tag_len + 1, M_VIRTFS_MNTTAG,
	    M_WAITOK | M_ZERO);

	virtio_read_device_config(dev,
	    offsetof(struct virtio_9pnet_config, mount_tag),
	    mount_tag, mount_tag_len);

	mount_tag_len++;
	chan->mount_tag_len = mount_tag_len;
	chan->mount_tag = mount_tag;

	ctx = device_get_sysctl_ctx(dev);
	tree = device_get_sysctl_tree(dev);
	SYSCTL_ADD_STRING(ctx, SYSCTL_CHILDREN(tree), OID_AUTO, "virtfs_mount_tag",
	    CTLFLAG_RD, chan->mount_tag, 0, "Mount tag");

	if (chan->vt9p_sglist == NULL) {
		error = ENOMEM;
		p9_debug(ERROR, "Cannot allocate sglist\n");
		goto out;
	}

	/* We expect one virtqueue, for requests. */
	error = vt9p_alloc_virtqueue(chan);

	if (error != 0) {
		p9_debug(ERROR, "Allocating the virtqueue failed \n");
		goto out;
	}

	error = virtio_setup_intr(dev, INTR_TYPE_MISC|INTR_MPSAFE);

	if (error != 0) {
		p9_debug(ERROR, "Cannot setup virtqueue interrupt\n");
		goto out;
	}
	error = virtqueue_enable_intr(chan->vt9p_vq);

	if (error != 0) {
		p9_debug(ERROR, "Cannot enable virtqueue interrupt\n");
		goto out;
	}

	mtx_lock(&global_chan_list_mtx);
	/* Insert the channel in global channel list */
	STAILQ_INSERT_HEAD(&global_chan_list, chan, chan_next);
	mtx_unlock(&global_chan_list_mtx);

	p9_debug(TRANS, "Attach successfully \n");

	return (0);
out:
	/* Something went wrong, detach the device */
	vt9p_detach(dev);
	return (error);
}

/*
 * Allocate a new virtio channel. This sets up a transport channel
 * for 9P communication
 */
static int
vt9p_create(struct p9_client *client, const char *mount_tag)
{
	struct vt9p_softc *sc, *chan;

	chan = NULL;

	/*
	 * Find out the corresponding channel for a client from global list
	 * of channels based on mount tag and attach it to client
	 */
	mtx_lock(&global_chan_list_mtx);
	STAILQ_FOREACH(sc, &global_chan_list, chan_next) {
		if (!strcmp(sc->mount_tag, mount_tag)) {
			chan = sc;
			break;
		}
	}
	mtx_unlock(&global_chan_list_mtx);

	/*
	 * If chan is already attached to a client then it cannot be used for
	 * another client.
	 */
	if (chan && chan->client != NULL) {
		p9_debug(TRANS, "Channel busy: used by clnt=%p\n",
		    chan->client);
		return (EBUSY);
	}

	/* If we dont have one, for now bail out.*/
	if (chan) {
		client->trans = (void *)chan;
		chan->client = client;
		client->trans_status = VIRTFS_CONNECT;
	} else {
		p9_debug(TRANS, "No Global channel with mount_tag=%s\n",
		    mount_tag);
		return (EINVAL);
	}

	return (0);
}

static struct p9_trans_module vt9p_trans = {
	.name = "virtio",
	.create = vt9p_create,
	.request = vt9p_request,
	.cancel = vt9p_cancel,
	.def = 1,
};

struct p9_trans_module *
p9_get_default_trans(void)
{

	return &vt9p_trans;
}

void
p9_put_trans(struct p9_client *clnt)
{
	struct vt9p_softc *chan;

	chan = clnt->trans;

	p9_debug(TRANS, "%s: its just a stub \n", __func__);
	chan->client = NULL;
}


static device_method_t vt9p_mthds[] = {
	/* Device methods. */
	DEVMETHOD(device_probe,	 vt9p_probe),
	DEVMETHOD(device_attach, vt9p_attach),
	DEVMETHOD(device_detach, vt9p_detach),
	DEVMETHOD_END
};

static driver_t vt9p_drv = {
	"9p_virtio",
	vt9p_mthds,
	sizeof(struct vt9p_softc)
};
static devclass_t vt9p_class;

static int
vt9p_modevent(module_t mod, int type, void *unused)
{
	int error;

	error = 0;

	switch (type) {
	case MOD_LOAD:
		p9_init_zones();
		break;
	case MOD_UNLOAD:
		p9_destroy_zones();
		break;
	case MOD_SHUTDOWN:
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}
	return (error);
}

#if __FreeBSD_version >= 1400058
DRIVER_MODULE(vt9p, virtio_pci, vt9p_drv,
    vt9p_modevent, 0);
#else
DRIVER_MODULE(vt9p, virtio_pci, vt9p_drv, vt9p_class,
    vt9p_modevent, 0);
#endif
MODULE_VERSION(vt9p, 1);
MODULE_DEPEND(vt9p, virtio, 1, 1, 1);
