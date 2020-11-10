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
 * 9P Protocol Support Code
 * This file provides the standard for the FS interactions with the Qemu interface as it can understand
 * only this protocol.
 *
 */

#include <sys/types.h>
#include <dev/virtio/virtio_fs_client.h>
#include <dev/virtio/virtio_fs_protocol.h>
#include <dev/virtio/virtio_fs_9p.h>

#define VIRTFS_MAXLEN 255

static int p9_buf_writef(struct p9_buffer *buf, int proto_version, const char *fmt, ...);
static void stat_free(struct p9_wstat *sbuf);

static void
stat_free(struct p9_wstat *stbuf)
{

	free(stbuf->name, M_TEMP);
	free(stbuf->uid, M_TEMP);
	free(stbuf->gid, M_TEMP);
	free(stbuf->muid, M_TEMP);
	free(stbuf->extension, M_TEMP);
}

static size_t
buf_read(struct p9_buffer *buf, void *data, size_t size)
{
	size_t len = min(buf->size - buf->offset, size);

	memcpy(data, &buf->sdata[buf->offset], len);
	buf->offset += len;

	return (size - len);
}

static size_t
buf_write(struct p9_buffer *buf, const void *data, size_t size)
{
	size_t len = min(buf->capacity - buf->size, size);

	memcpy(&buf->sdata[buf->size], data, len);
	buf->size += len;

	return (size - len);
}

/*
 * Main buf_read routine. This copies the data from the buffer into the
 * respective values based on the data type.
 * Here
 *	  b - int8_t
 *	  w - int16_t
 *	  d - int32_t
 *	  q - int64_t
 *	  s - string
 *	  Q - qid
 *	  S - stat
 *	  D - data blob (int32_t size followed by void *, results are not freed)
 *	  T - array of strings (int16_t count, followed by strings)
 *	  R - array of qids (int16_t count, followed by qids)
 *	  ? - if optional = 1, continue parsing
 */
static int
p9_buf_vreadf(struct p9_buffer *buf, int proto_version, const char *fmt,
    va_list ap)
{
	const char *ptr;
	int err = 0;

        p9_debug(ERROR, "%s: called: %s\n", __func__, fmt);
        p9_debug(ERROR, "%s: buf->size: %u\n", __func__, buf->size);
        p9_debug(ERROR, "%s: buf->tag: %hu\n", __func__, buf->tag);
        p9_debug(ERROR, "%s: buf->id: %hu\n", __func__, buf->id);

	/*
        for (int i = 0; i < sizeof(uint32_t); i++) {
        	p9_debug(ERROR, "%02X", buf->size[i]);
        }
        p9_debug(ERROR, "\n");
        p9_debug(ERROR, "%s: tag: ", __func__);
        for (int i = 0; i < sizeof(uint16_t); i++) {
        	p9_debug(ERROR, "%02X", buf->tag[i]);
        }
        p9_debug(ERROR, "\n");
	*/

	for (ptr = fmt; *ptr; ptr++) {
		switch (*ptr) {
		case 'b':
		{
			int8_t *val = va_arg(ap, int8_t *);

			if (buf_read(buf, val, sizeof(*val))) {
		        	p9_debug(ERROR, "%s: b: buf_read failed\n", __func__);
				err = EFAULT;
			}
			break;
		}
		case 'w':
		{
			int16_t *val = va_arg(ap, int16_t *);

			if (buf_read(buf, val, sizeof(*val)))
				err = EFAULT;
			break;
		}
		case 'd':
		{
			int32_t *val = va_arg(ap, int32_t *);

			if (buf_read(buf, val, sizeof(*val))) {
		                p9_debug(ERROR, "%s: d: buf_read failed: %d\n", __func__, err);
				err = EFAULT;
			}
			break;
		}
		case 'q':
		{
			int64_t *val = va_arg(ap, int64_t *);

			if (buf_read(buf, val, sizeof(*val))) {
		        	p9_debug(ERROR, "%s: q: failed\n", __func__);
				err = EFAULT;
			}
			break;
		}
		case 's':
		{
			char **sptr_p = va_arg(ap, char **);
			uint16_t len;
			char *sptr;

			err = buf_read(buf, &len, sizeof(uint16_t));
			if (err) {
		                p9_debug(ERROR, "p9_buf_vreadf: s: buf_read failed: %d\n", err);
				break;
			}
		        p9_debug(ERROR, "p9_buf_vreadf: s: len: %d\n", len);

			sptr = malloc(len + 1, M_TEMP, M_NOWAIT | M_ZERO);

			if (buf_read(buf, sptr, len)) {
				err = EFAULT;
				free(sptr, M_TEMP);
				sptr = NULL;
			} else {
				(sptr)[len] = 0;
				*sptr_p = sptr;
			}
			break;
		}
		case 'Q':
		{
			struct p9_qid *qid = va_arg(ap, struct p9_qid *);

			err = p9_buf_readf(buf, proto_version, "bdq",
			    &qid->type, &qid->version, &qid->path);

			break;
		}
		case 'S':
		{
			struct p9_wstat *stbuf = va_arg(ap, struct p9_wstat *);

			err = p9_buf_readf(buf, proto_version, "wwdQdddqssss?sddd",
			    &stbuf->size, &stbuf->type, &stbuf->dev, &stbuf->qid,
			    &stbuf->mode, &stbuf->atime, &stbuf->mtime, &stbuf->length,
			    &stbuf->name, &stbuf->uid, &stbuf->gid, &stbuf->muid,
			    &stbuf->extension, &stbuf->n_uid, &stbuf->n_gid, &stbuf->n_muid);

			if (err)
				stat_free(stbuf);
			break;
		}
		case 'D':
		{
			uint32_t *count = va_arg(ap, uint32_t *);
			void **data = va_arg(ap, void **);

			err = buf_read(buf, count, sizeof(uint32_t));
			if (err == 0) {
				*count = MIN(*count, buf->size - buf->offset);
				*data = &buf->sdata[buf->offset];
			}
			break;
		}
		case 'T':
		{
			uint16_t *nwname_p = va_arg(ap, uint16_t *);
			char ***wnames_p = va_arg(ap, char ***);
			uint16_t nwname;
			char **wnames;
			int i;

			err = buf_read(buf, nwname_p, sizeof(uint16_t));
			if (err != 0)
				break;

			nwname = *nwname_p;
			wnames = malloc(sizeof(char *) * nwname, M_TEMP, M_NOWAIT | M_ZERO);

			for (i = 0; i < nwname && (err == 0); i++)
				err = p9_buf_readf(buf, proto_version, "s", &wnames[i]);

			if (err != 0) {
				for (i = 0; i < nwname; i++)
					free((wnames)[i], M_TEMP);
				free(wnames, M_TEMP);
			} else
				*wnames_p = wnames;
			break;
		}
		case 'R':
		{
			uint16_t *nwqid_p = va_arg(ap, uint16_t *);
			struct p9_qid **wqids_p = va_arg(ap, struct p9_qid **);
			uint16_t nwqid;
			struct p9_qid *wqids;
			int i;

			wqids = NULL;
			err = buf_read(buf, nwqid_p, sizeof(uint16_t));
			if (err != 0) {
		        	p9_debug(ERROR, "%s: p9_buf_vreadf: R: buf_read1 failed\n", __func__);
				break;
			}

			nwqid = *nwqid_p;
		        p9_debug(ERROR, "%s: p9_buf_vreadf: R: nqid: %d\n", __func__, nwqid);
			wqids = malloc(nwqid * sizeof(struct p9_qid), M_TEMP, M_NOWAIT | M_ZERO);

			for (i = 0; i < nwqid && (err == 0); i++) {
				err = p9_buf_readf(buf, proto_version, "Q", &(wqids)[i]);
			}

			if (err != 0) {
				free(wqids, M_TEMP);
			} else
				*wqids_p = wqids;

			break;
		}
		case '?':
		{
		        p9_debug(ERROR, "p9_buf_vreadf: ?: proto_version: %d\n", proto_version);
			if ((proto_version != p9_proto_2000u) && (proto_version != p9_proto_2000L))
				return 0;
			break;
		}
		default:
			break;
		}

		if (err != 0)
			break;
	}

	return (err);
}

/*
 * Main buf_write routine. This copies the data into the buffer from the
 * respective values based on the data type.
 * Here
 *	  b - int8_t
 *	  w - int16_t
 *	  d - int32_t
 *	  q - int64_t
 *	  s - string
 *	  Q - qid
 *	  S - stat
 *	  D - data blob (int32_t size followed by void *, results are not freed)
 *	  T - array of strings (int16_t count, followed by strings)
 *	  W - string of a specific length
 *	  R - array of qids (int16_t count, followed by qids)
 *	  ? - if optional = 1, continue parsing
 */

int
p9_buf_vwritef(struct p9_buffer *buf, int proto_version, const char *fmt,
	va_list ap)
{
	const char *ptr;
	int err = 0;

	for (ptr = fmt; *ptr; ptr++) {
		switch (*ptr) {
		case 'b':
		{
			int8_t val = va_arg(ap, int);

			if (buf_write(buf, &val, sizeof(val)))
				err = EFAULT;
			break;
		}
		case 'w':
		{
			int16_t val = va_arg(ap, int);

			if (buf_write(buf, &val, sizeof(val)))
				err = EFAULT;
			break;
		}
		case 'd':
		{
			int32_t val = va_arg(ap, int32_t);

			if (buf_write(buf, &val, sizeof(val)))
				err = EFAULT;
			break;
		}
		case 'q':
		{
			int64_t val = va_arg(ap, int64_t);

			if (buf_write(buf, &val, sizeof(val)))
				err = EFAULT;

			break;
		}
		case 's':
		{
			const char *sptr = va_arg(ap, const char *);
		        uint16_t len = 0;

	                if (sptr)
			    len = MIN(strlen(sptr), VIRTFS_MAXLEN);

			err = buf_write(buf, &len, sizeof(uint16_t));
			if (!err && buf_write(buf, sptr, len))
				err = EFAULT;
			break;
		}
		case 'Q':
		{
			const struct p9_qid *qid = va_arg(ap, const struct p9_qid *);

			err = p9_buf_writef(buf, proto_version, "bdq",
			    qid->type, qid->version, qid->path);
			break;
		}
		case 'S':
		{
			struct p9_wstat *stbuf = va_arg(ap, struct p9_wstat *);

			err = p9_buf_writef(buf, proto_version,
			    "wwdQdddqssss?sddd", stbuf->size, stbuf->type, stbuf->dev, &stbuf->qid,
			    stbuf->mode, stbuf->atime, stbuf->mtime, stbuf->length, stbuf->name,
			    stbuf->uid, stbuf->gid, stbuf->muid, stbuf->extension, stbuf->n_uid,
			    stbuf->n_gid, stbuf->n_muid);

			if (err != 0)
				stat_free(stbuf);

			break;
		}
		case 'D':
		{
			uint32_t count = va_arg(ap, uint32_t);
			void *data = va_arg(ap, void *);

			err = buf_write(buf, &count, sizeof(uint32_t));
			if ((err == 0) && buf_write(buf, data, count))
				err = EFAULT;

			break;
		}
		case 'T':
		{
                        char *wname = va_arg(ap, char *);
                        uint16_t wnamelen = va_arg(ap, size_t);
                        uint16_t nwname = (wname == NULL) ? 0: 1;

			err = buf_write(buf, &nwname, sizeof(uint16_t));
			if (err == 0 && nwname > 0) {
				err = p9_buf_writef(buf, proto_version, "W", wname, wnamelen);
				if (err != 0)
					break;
			}
			break;
		}
                case 'W':
                {
                        const char *sptr = va_arg(ap, const char*);
                        uint16_t len = va_arg(ap, int);

			err = buf_write(buf, &len, sizeof(uint16_t));
			if (!err && buf_write(buf, sptr, len))
				err = EFAULT;
			break;

                }
		case 'R':
		{
			uint16_t nwqid = va_arg(ap, int);
			struct p9_qid *wqids = va_arg(ap, struct p9_qid *);
			int i;

			err = buf_write(buf, &nwqid, sizeof(uint16_t));
			if (err == 0) {

				for (i = 0; i < nwqid; i++) {
					err = p9_buf_writef(buf, proto_version, "Q", &wqids[i]);
					if (err != 0)
						break;
				}
			}
			break;
		}
		case '?':
		{
			if ((proto_version != p9_proto_2000u) && (proto_version != p9_proto_2000L))
				return 0;
			break;
		}
		default:
			break;

		}

		if (err != 0)
			break;
	}

	return (err);
}

/* Helper for buf_read*/
int
p9_buf_readf(struct p9_buffer *buf, int proto_version, const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = p9_buf_vreadf(buf, proto_version, fmt, ap);
	va_end(ap);

	return (ret);
}

/*Helper for buf_write */
static int
p9_buf_writef(struct p9_buffer *buf, int proto_version, const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = p9_buf_vwritef(buf, proto_version, fmt, ap);
	va_end(ap);

	return ret;
}

/* Helper for stat_read. while getting/setting attributes of files.(stats)  */
int
p9stat_read(struct p9_client *clnt, char *buf, size_t len, struct p9_wstat *st)
{
	struct p9_buffer msg_buf;
	int ret;

	msg_buf.size = len;
	msg_buf.capacity = len;
	msg_buf.sdata = buf;
	msg_buf.offset = 0;

	ret = p9_buf_readf(&msg_buf, clnt->proto_version, "S", st);
	if (ret) {
		p9_debug(ERROR, "p9stat_read failed: %d\n", ret);
	}

	return ret;
}

/*
 * P9_header preparation routine. All p9 buffers have to have this header(QEMU_HEADER) at the
 * front of the buffer.
 */
int
p9_buf_prepare(struct p9_buffer *buf, int8_t type, struct p9_client *clnt)
{
	uint16_t tag;

        tag = p9_tag_create(clnt);
	if (tag == P9_NOTAG)
		return EAGAIN;
	buf->id = type;
	buf->tag = tag;
	return p9_buf_writef(buf, 0, "dbw", 0, type, tag);
}

/*
 * Final write to the buffer, this is the total size of the buffer. Since the buffer length can
 * vary with request, this is computed at the end just before sending the request to the driver
 */
int
p9_buf_finalize(struct p9_client *clnt, struct p9_buffer *buf)
{
	int size = buf->size;
	int err;

	buf->size = 0;
	err = p9_buf_writef(buf, 0, "d", size);
	buf->size = size;

	p9_debug(PROTO, "size=%d type: %d tag: %d\n",
	    buf->size, buf->id, buf->tag);

	return err;
}

/*Reset values of the buffer*/
void
p9_buf_reset(struct p9_buffer *buf)
{

	buf->offset = 0;
	buf->size = 0;
}

/*
 * Directory entry read with the buf we have. Call this once we have the buf to parse.
 * This buf, obtained from the server, is parsed to make dirent in readdir.
 */
int
p9_dirent_read(struct p9_client *clnt, char *buf, int start, int len,
	struct p9_dirent *dent)
{
	struct p9_buffer msg_buf;
	int ret;
	char *nameptr;
	uint16_t sle;

	msg_buf.size = len;
	msg_buf.capacity = len;
	msg_buf.sdata = buf;
	msg_buf.offset = start;

	ret = p9_buf_readf(&msg_buf, clnt->proto_version, "Qqbs", &dent->qid,
	    &dent->d_off, &dent->d_type, &nameptr);
	if (ret) {
		p9_debug(ERROR, " p9_dirent_read failed: %d\n", ret);
		goto out;
	}

	sle = strlen(nameptr);
	strncpy(dent->d_name, nameptr, sle);
	dent->len = sle;
	free(nameptr, M_TEMP);
out:
	return msg_buf.offset;
}
