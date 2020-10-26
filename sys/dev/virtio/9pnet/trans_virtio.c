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
 * The Virtio 9p transport driver
 */

#include <dev/virtio/virtio_fs_client.h>
#include <dev/virtio/virtio_fs_protocol.h>
#include <dev/virtio/virtio_fs_9p.h>
#include "transport.h"
#include <sys/errno.h>
#include <sys/module.h>
#include <sys/sglist.h>
#include <sys/queue.h>
#include <sys/bus.h>
#include <sys/kthread.h>
#include <sys/condvar.h>
#include <machine/bus.h>
#include <dev/virtio/virtio.h>
#include <dev/virtio/virtqueue.h>
#include <dev/virtio/virtio_ring.h>

#define VT9P_MTX(_sc) (&(_sc)->vt9p_mtx)
#define VT9P_LOCK(_sc) mtx_lock(VT9P_MTX(_sc))
#define VT9P_UNLOCK(_sc) mtx_unlock(VT9P_MTX(_sc))
#define VT9P_LOCK_INIT(_sc) mtx_init(VT9P_MTX(_sc), \
    "VIRTIO 9P CHAN lock", NULL, MTX_DEF)
#define VT9P_LOCK_DESTROY(_sc) mtx_destroy(VT9P_MTX(_sc))
#define MAX_SUPPORTED_SGS 20

struct vt9p_softc *global_ctx;

struct vt9p_softc {
	device_t vt9p_dev;
	struct mtx vt9p_mtx;
	struct sglist *vt9p_sglist;
	struct cv submit_cv;
	struct p9_client *client;
	struct virtqueue *vt9p_vq;
	int max_nsegs;
};

/* We don't currently allow canceling of virtio requests */
static int
vt9p_cancel(struct p9_client *client, struct p9_req_t *req)
{

	return (1);
}

/*
 * Request handler. This is called for every request submitted to the host
 * It basically maps the tc/rc buffers to sg lists and submits the requests
 * into the virtqueue. Since we have implemented a synchronous version, the
 * submission thread sleeps until the ack in the interrupt wakes it up. Once
 * it wakes up, it returns back to the VIRTFS layer. The rc buffer is then
 * processed and completed to its upper layers.
 */
static int
vt9p_request(struct p9_client *client, struct p9_req_t *req)
{
	int err;
	struct vt9p_softc *chan = client->trans;
	struct p9_req_t *curreq;
	int readable, writable;
	struct sglist *sg;
	struct virtqueue *vq;

	sg = chan->vt9p_sglist;
	vq = chan->vt9p_vq;

	p9_debug(TRANS, "9p debug: virtio request\n");

	/* Grab the channel lock*/
	VT9P_LOCK(chan);
	sglist_reset(sg);
	/* Handle out VirtIO ring buffers */
	err = sglist_append(sg, req->tc->sdata, req->tc->size);
	if (err != 0) {
		p9_debug(ERROR, "sglist append failed\n");
		return (err);
	}
	readable = sg->sg_nseg;

	err = sglist_append(sg, req->rc->sdata, req->rc->capacity);
	if (err != 0) {
		p9_debug(ERROR, " sglist append failed\n");
		return (err);
	}
	writable = sg->sg_nseg - readable;

req_retry:
	err = virtqueue_enqueue(vq, req, sg, readable, writable);

	if (err != 0) {
		if (err == ENOSPC) {
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
			msleep(chan, VT9P_MTX(chan), 0, "chan lock", 0);
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
	chan = (struct vt9p_softc *)xsc;
	struct virtqueue *vq = chan->vt9p_vq;

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
	device_t dev = sc->vt9p_dev;

	VQ_ALLOC_INFO_INIT(&vq_info, sc->max_nsegs,
	    vt9p_intr_complete, sc, &sc->vt9p_vq,
	    "%s request", device_get_nameunit(dev));

	return (virtio_alloc_virtqueues(dev, 0, 1, &vq_info));
}

static int
vt9p_probe(device_t dev)
{

	/* VIRTIO_ID_9P is already defined */
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
	VT9P_LOCK_DESTROY(sc);
	cv_destroy(&sc->submit_cv);

	return (0);
}

static int
vt9p_attach(device_t dev)
{
	int err;
	struct vt9p_softc *chan;

	chan = device_get_softc(dev);
	chan->vt9p_dev = dev;
	/* Init the channel lock. */
	VT9P_LOCK_INIT(chan);
	/* Initialize the condition variable */
	cv_init(&chan->submit_cv, "Conditional variable for submit queue" );
	chan->max_nsegs = MAX_SUPPORTED_SGS;
	chan->vt9p_sglist = sglist_alloc(chan->max_nsegs, M_NOWAIT);

	if (chan->vt9p_sglist == NULL) {
		err = ENOMEM;
		p9_debug(ERROR, "Cannot allocate sglist\n");
		goto out;
	}

	/* We expect one virtqueue, for requests. */
	err = vt9p_alloc_virtqueue(chan);

	if (err != 0) {
		p9_debug(ERROR, "Allocating the virtqueue failed \n");
		goto out;
	}

	err = virtio_setup_intr(dev, INTR_TYPE_MISC|INTR_MPSAFE);

	if (err != 0) {
		p9_debug(ERROR, "Cannot setup virtqueue interrupt\n");
		goto out;
	}
	err = virtqueue_enable_intr(chan->vt9p_vq);

	if (err != 0) {
		p9_debug(ERROR, "Cannot enable virtqueue interrupt\n");
		goto out;
	}

	/* We have only one global channel for now.*/
	global_ctx = chan;
	p9_debug(TRANS, "Attach successfully \n");

	return (0);

out:
	/* Something went wrong, detach the device */
	vt9p_detach(dev);

	return (err);
}

static int
vt9p_create(struct p9_client *client)
{
	struct vt9p_softc *chan = NULL;

	if (global_ctx != NULL)
		chan = global_ctx;
	/*
	 * For now I dont see any other place to put this. We do not support
	 * multiple mounts on VIRTFS still, so as soon as we see this channel
	 * already attached to another client, we back off and return error.
	 * Once that is supported, we can remove this.
	 */
	if (chan && chan->client != NULL)
		return EMFILE;

	/* If we dont have one, for now bail out.*/
	if (chan != NULL) {
		client->trans = (void *)chan;
		chan->client = client;
		client->trans_status = VIRTFS_CONNECT;
	} else {
		p9_debug(TRANS, "No Global channel. Others not supported yet \n");
		return (-1);
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
p9_put_trans(struct p9_trans_module *m)
{

	p9_debug(TRANS, "%s: its just a stub \n", __func__);
	global_ctx->client = NULL;
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
	int error = 0;

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

DRIVER_MODULE(vt9p, virtio_pci, vt9p_drv, vt9p_class,
    vt9p_modevent, 0);
MODULE_VERSION(vt9p, 1);
MODULE_DEPEND(vt9p, virtio, 1, 1, 1);
