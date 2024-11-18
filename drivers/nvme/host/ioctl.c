// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2011-2014, Intel Corporation.
 * Copyright (c) 2017-2021 Christoph Hellwig.
 */
#include <linux/ptrace.h>	/* for force_successful_syscall_return */
#include <linux/nvme_ioctl.h>
#include "nvme.h"

/*
 * Convert integer values from ioctl structures to user pointers, silently
 * ignoring the upper bits in the compat case to match behaviour of 32-bit
 * kernels.
 */
static void __user *nvme_to_user_ptr(uintptr_t ptrval)
{
	if (in_compat_syscall())
		ptrval = (compat_uptr_t)ptrval;
	return (void __user *)ptrval;
}
/* This overlays struct io_uring_cmd pdu (40 bytes) */
struct nvme_uring_cmd {
	u32 ioctl_cmd;
	u32 meta_len;
	void __user *argp;
	union {
		struct bio *bio;
		struct request *req;
	};
	void *meta; /* kernel-resident buffer */
	void __user *meta_buffer;
};

static inline bool is_polling_enabled(struct io_uring_cmd *ioucmd,
				      struct request *req)
{
	return (ioucmd->flags & URING_CMD_POLLED) && blk_rq_is_poll(req);
}

static struct nvme_uring_cmd *nvme_uring_cmd(struct io_uring_cmd *ioucmd)
{
	return (struct nvme_uring_cmd *)&ioucmd->pdu;
}

static void nvme_pt_task_cb(struct io_uring_cmd *ioucmd)
{
	struct nvme_uring_cmd *cmd = nvme_uring_cmd(ioucmd);
	struct nvme_passthru_cmd64 __user *ptcmd64 = cmd->argp;
	struct request *req = cmd->req;
	int status;
	u64 result;
	struct bio *bio = req->bio;

	if (nvme_req(req)->flags & NVME_REQ_CANCELLED)
		status = -EINTR;
	else
		status = nvme_req(req)->status;
	result = le64_to_cpu(nvme_req(req)->result.u64);

	/* we can free request */
	blk_mq_free_request(req);
	blk_rq_unmap_user(bio);

	if (cmd->meta) {
		if (status)
			if (copy_to_user(cmd->meta_buffer, cmd->meta, cmd->meta_len))
				status = -EFAULT;
		kfree(cmd->meta);
	}

	if (put_user(result, &ptcmd64->result))
		status = -EFAULT;
	io_uring_cmd_done(ioucmd, status);
}

static void nvme_end_async_pt(struct request *req, blk_status_t err)
{
	struct io_uring_cmd *ioucmd = req->end_io_data;
	struct nvme_uring_cmd *cmd = nvme_uring_cmd(ioucmd);
	/* extract bio before reusing the same field for request */
	struct bio *bio = cmd->bio;

	cmd->req = req;
	req->bio = bio;

	/*IO can be completed immediately when the callback
	 * is in the same task context
	 */
	if (is_polling_enabled(ioucmd, req)) {
		nvme_pt_task_cb(ioucmd);
	} else {
		/* this takes care of setting up task-work */
		io_uring_cmd_complete_in_task(ioucmd, nvme_pt_task_cb);
	}
}

static void nvme_setup_uring_cmd_data(struct request *rq,
		struct io_uring_cmd *ioucmd, void *meta,
		void __user *meta_buffer, u32 meta_len, bool write)
{
	struct nvme_uring_cmd *cmd = nvme_uring_cmd(ioucmd);

	/* to free bio on completion, as req->bio will be null at that time */
	cmd->bio = rq->bio;
	/* meta update is required only for read requests */
	if (meta && !write) {
		cmd->meta = meta;
		cmd->meta_buffer = meta_buffer;
		cmd->meta_len = meta_len;
	} else {
		cmd->meta = NULL;
	}
	rq->end_io_data = ioucmd;
}

static void *nvme_add_user_metadata(struct bio *bio, void __user *ubuf,
		unsigned len, u32 seed, bool write)
{
	struct bio_integrity_payload *bip;
	int ret = -ENOMEM;
	void *buf;

	buf = kmalloc(len, GFP_KERNEL);
	if (!buf)
		goto out;

	ret = -EFAULT;
	if (write && copy_from_user(buf, ubuf, len))
		goto out_free_meta;

	bip = bio_integrity_alloc(bio, GFP_KERNEL, 1);
	if (IS_ERR(bip)) {
		ret = PTR_ERR(bip);
		goto out_free_meta;
	}

	bip->bip_iter.bi_size = len;
	bip->bip_iter.bi_sector = seed;
	ret = bio_integrity_add_page(bio, virt_to_page(buf), len,
			offset_in_page(buf));
	if (ret == len)
		return buf;
	ret = -ENOMEM;
out_free_meta:
	kfree(buf);
out:
	return ERR_PTR(ret);
}

static inline bool nvme_is_fixedb_passthru(struct io_uring_cmd *ioucmd)
{
	return ((ioucmd) && (ioucmd->flags & URING_CMD_FIXEDBUFS));
}

int nvme_submit_user_cmd(struct request_queue *q,
		struct nvme_command *cmd, u64 ubuffer,
		unsigned bufflen, void __user *meta_buffer, unsigned meta_len,
		u32 meta_seed, u64 *result, unsigned timeout,
		struct io_uring_cmd *ioucmd, unsigned int rq_flags)
{
	bool write = nvme_is_write(cmd);
	struct nvme_ns *ns = q->queuedata;
	struct block_device *bdev = ns ? ns->disk->part0 : NULL;
	struct request *req;
	struct bio *bio = NULL;
	void *meta = NULL;
	int ret;

	req = nvme_alloc_request(q, cmd, 0, rq_flags);
	if (IS_ERR(req))
		return PTR_ERR(req);

	if (timeout)
		req->timeout = timeout;
	nvme_req(req)->flags |= NVME_REQ_USERCMD;

	if (ubuffer && bufflen) {
		if (likely(!nvme_is_fixedb_passthru(ioucmd)))
			ret = blk_rq_map_user(q, req, NULL, nvme_to_user_ptr(ubuffer),
					bufflen, GFP_KERNEL);
		else
			ret = blk_rq_map_user_fixedb(q, req, ubuffer, bufflen,
					&nvme_bio_pool, ioucmd);
		if (ret)
			goto out;
		bio = req->bio;
		if (bdev)
			bio_set_dev(bio, bdev);
		if (bdev && meta_buffer && meta_len) {
			meta = nvme_add_user_metadata(bio, meta_buffer, meta_len,
					meta_seed, write);
			if (IS_ERR(meta)) {
				ret = PTR_ERR(meta);
				goto out_unmap;
			}
			req->cmd_flags |= REQ_INTEGRITY;
		}
	}
	if (ioucmd) { /* async dispatch */
		nvme_setup_uring_cmd_data(req, ioucmd, meta, meta_buffer,
				meta_len, write);

		if (bio && is_polling_enabled(ioucmd, req)) {
			ioucmd->bio = bio;
			bio->bi_opf |= REQ_POLLED;
		}

		blk_execute_rq_nowait(ns ? ns->disk : NULL, req, 0,
					nvme_end_async_pt);
		return 0;
	}

	ret = nvme_execute_passthru_rq(req);
	if (result)
		*result = le64_to_cpu(nvme_req(req)->result.u64);
	if (meta && !ret && !write) {
		if (copy_to_user(meta_buffer, meta, meta_len))
			ret = -EFAULT;
	}
	kfree(meta);
 out_unmap:
	if (bio)
		blk_rq_unmap_user(bio);
 out:
	blk_mq_free_request(req);
	return ret;
}
EXPORT_SYMBOL_GPL(nvme_submit_user_cmd);


static int nvme_submit_io(struct nvme_ns *ns, struct nvme_user_io __user *uio)
{
	struct nvme_user_io io;
	struct nvme_command c;
	unsigned length, meta_len;
	void __user *metadata;
	unsigned int rq_flags = 0;

	if (copy_from_user(&io, uio, sizeof(io)))
		return -EFAULT;

	if (io.flags & NVME_HIPRI)
		rq_flags |= REQ_POLLED;

	switch (io.opcode) {
	case nvme_cmd_write:
	case nvme_cmd_read:
	case nvme_cmd_compare:
		break;
	default:
		return -EINVAL;
	}

	length = (io.nblocks + 1) << ns->lba_shift;

	if ((io.control & NVME_RW_PRINFO_PRACT) &&
	    ns->ms == sizeof(struct t10_pi_tuple)) {
		/*
		 * Protection information is stripped/inserted by the
		 * controller.
		 */
		if (nvme_to_user_ptr(io.metadata))
			return -EINVAL;
		meta_len = 0;
		metadata = NULL;
	} else {
		meta_len = (io.nblocks + 1) * ns->ms;
		metadata = nvme_to_user_ptr(io.metadata);
	}

	if (ns->features & NVME_NS_EXT_LBAS) {
		length += meta_len;
		meta_len = 0;
	} else if (meta_len) {
		if ((io.metadata & 3) || !io.metadata)
			return -EINVAL;
	}

	memset(&c, 0, sizeof(c));
	c.rw.opcode = io.opcode;
	c.rw.flags = 0;
	c.rw.nsid = cpu_to_le32(ns->head->ns_id);
	c.rw.slba = cpu_to_le64(io.slba);
	c.rw.length = cpu_to_le16(io.nblocks);
	c.rw.control = cpu_to_le16(io.control);
	c.rw.dsmgmt = cpu_to_le32(io.dsmgmt);
	c.rw.reftag = cpu_to_le32(io.reftag);
	c.rw.apptag = cpu_to_le16(io.apptag);
	c.rw.appmask = cpu_to_le16(io.appmask);

	return nvme_submit_user_cmd(ns->queue, &c,
			io.addr, length, metadata, meta_len,
			lower_32_bits(io.slba), NULL, 0, NULL, rq_flags);
}

static bool nvme_validate_passthru_nsid(struct nvme_ctrl *ctrl,
					struct nvme_ns *ns, __u32 nsid)
{
	if (ns && nsid != ns->head->ns_id) {
		dev_err(ctrl->device,
			"%s: nsid (%u) in cmd does not match nsid (%u)"
			"of namespace\n",
			current->comm, nsid, ns->head->ns_id);
		return false;
	}

	return true;
}

static int nvme_user_cmd(struct nvme_ctrl *ctrl, struct nvme_ns *ns,
			struct nvme_passthru_cmd __user *ucmd)
{
	struct nvme_passthru_cmd cmd;
	struct nvme_command c;
	unsigned int rq_flags = 0;
	unsigned timeout = 0;
	u64 result;
	int status;
	int no_user_mem = 0;
	struct nvme_passthru_cmd* temp = ucmd;

	if (!capable(CAP_SYS_ADMIN))
		return -EACCES;
	if (copy_from_user(&cmd, ucmd, sizeof(cmd))) {
		memcpy(&cmd, ucmd, sizeof(ucmd));
		no_user_mem = 1;
		cmd.timeout_ms = ucmd->timeout_ms;
  }
	if (cmd.flags & NVME_HIPRI)
		rq_flags |= REQ_POLLED;
	if (!nvme_validate_passthru_nsid(ctrl, ns, cmd.nsid))
		return -EINVAL;

	memset(&c, 0, sizeof(c));
	c.common.opcode = cmd.opcode;
	c.common.flags = 0;
	c.common.nsid = cpu_to_le32(cmd.nsid);
	c.common.cdw2[0] = cpu_to_le32(cmd.cdw2);
	c.common.cdw2[1] = cpu_to_le32(cmd.cdw3);
	c.common.cdw10 = cpu_to_le32(cmd.cdw10);
	c.common.cdw11 = cpu_to_le32(cmd.cdw11);
	c.common.cdw12 = cpu_to_le32(cmd.cdw12);
	c.common.cdw13 = cpu_to_le32(cmd.cdw13);
	c.common.cdw14 = cpu_to_le32(cmd.cdw14);
	c.common.cdw15 = cpu_to_le32(cmd.cdw15);

	if (cmd.timeout_ms)
		timeout = msecs_to_jiffies(cmd.timeout_ms);

	status = nvme_submit_user_cmd(ns ? ns->queue : ctrl->admin_q, &c,
			cmd.addr, cmd.data_len, nvme_to_user_ptr(cmd.metadata),
			cmd.metadata_len, 0, &result, timeout, NULL, rq_flags);

	if (status >= 0) {
		if (no_user_mem) {
			temp->result = result;
		} else if (put_user(result, &ucmd->result)) {
			return -EFAULT;
		}
	}

	return status;
}

static int nvme_user_cmd64(struct nvme_ctrl *ctrl, struct nvme_ns *ns,
			struct nvme_passthru_cmd64 __user *ucmd,
			struct io_uring_cmd *ioucmd)
{
	struct nvme_passthru_cmd64 cmd;
	struct nvme_command c;
	unsigned int rq_flags = 0;
	unsigned timeout = 0;
	int status;

	if (!capable(CAP_SYS_ADMIN))
		return -EACCES;
	if (copy_from_user(&cmd, ucmd, sizeof(cmd)))
		return -EFAULT;
	if (cmd.flags & NVME_HIPRI)
		rq_flags |= REQ_POLLED;

	if (!nvme_validate_passthru_nsid(ctrl, ns, cmd.nsid))
		return -EINVAL;

	memset(&c, 0, sizeof(c));
	c.common.opcode = cmd.opcode;
	c.common.flags = 0;
	c.common.nsid = cpu_to_le32(cmd.nsid);
	c.common.cdw2[0] = cpu_to_le32(cmd.cdw2);
	c.common.cdw2[1] = cpu_to_le32(cmd.cdw3);
	c.common.cdw10 = cpu_to_le32(cmd.cdw10);
	c.common.cdw11 = cpu_to_le32(cmd.cdw11);
	c.common.cdw12 = cpu_to_le32(cmd.cdw12);
	c.common.cdw13 = cpu_to_le32(cmd.cdw13);
	c.common.cdw14 = cpu_to_le32(cmd.cdw14);
	c.common.cdw15 = cpu_to_le32(cmd.cdw15);

	if (cmd.timeout_ms)
		timeout = msecs_to_jiffies(cmd.timeout_ms);

	status = nvme_submit_user_cmd(ns ? ns->queue : ctrl->admin_q, &c,
			cmd.addr, cmd.data_len, nvme_to_user_ptr(cmd.metadata),
			cmd.metadata_len, 0, &cmd.result, timeout, ioucmd, rq_flags);

	if (!ioucmd && status >= 0) {
		if (put_user(cmd.result, &ucmd->result))
			return -EFAULT;
	}

	return status;
}

static bool is_ctrl_ioctl(unsigned int cmd)
{
	if (cmd == NVME_IOCTL_ADMIN_CMD || cmd == NVME_IOCTL_ADMIN64_CMD)
		return true;
	if (is_sed_ioctl(cmd))
		return true;
	return false;
}

static int nvme_ctrl_ioctl(struct nvme_ctrl *ctrl, unsigned int cmd,
		void __user *argp)
{
	switch (cmd) {
	case NVME_IOCTL_ADMIN_CMD:
		return nvme_user_cmd(ctrl, NULL, argp);
	case NVME_IOCTL_ADMIN64_CMD:
		return nvme_user_cmd64(ctrl, NULL, argp, NULL);
	default:
		return sed_ioctl(ctrl->opal_dev, cmd, argp);
	}
}

#ifdef COMPAT_FOR_U64_ALIGNMENT
struct nvme_user_io32 {
	__u8	opcode;
	__u8	flags;
	__u16	control;
	__u16	nblocks;
	__u16	rsvd;
	__u64	metadata;
	__u64	addr;
	__u64	slba;
	__u32	dsmgmt;
	__u32	reftag;
	__u16	apptag;
	__u16	appmask;
} __attribute__((__packed__));
#define NVME_IOCTL_SUBMIT_IO32	_IOW('N', 0x42, struct nvme_user_io32)
#endif /* COMPAT_FOR_U64_ALIGNMENT */

static int nvme_ns_ioctl(struct nvme_ns *ns, unsigned int cmd,
		void __user *argp)
{
	switch (cmd) {
	case NVME_IOCTL_ID:
		force_successful_syscall_return();
		return ns->head->ns_id;
	case NVME_IOCTL_IO_CMD:
		return nvme_user_cmd(ns->ctrl, ns, argp);
	/*
	 * struct nvme_user_io can have different padding on some 32-bit ABIs.
	 * Just accept the compat version as all fields that are used are the
	 * same size and at the same offset.
	 */
#ifdef COMPAT_FOR_U64_ALIGNMENT
	case NVME_IOCTL_SUBMIT_IO32:
#endif
	case NVME_IOCTL_SUBMIT_IO:
		return nvme_submit_io(ns, argp);
	case NVME_IOCTL_IO64_CMD:
		return nvme_user_cmd64(ns->ctrl, ns, argp, NULL);
	default:
		return -ENOTTY;
	}
}

static int __nvme_ioctl(struct nvme_ns *ns, unsigned int cmd, void __user *arg)
{
       if (is_ctrl_ioctl(cmd))
               return nvme_ctrl_ioctl(ns->ctrl, cmd, arg);
       return nvme_ns_ioctl(ns, cmd, arg);
}

int nvme_ioctl(struct block_device *bdev, fmode_t mode,
		unsigned int cmd, unsigned long arg)
{
	struct nvme_ns *ns = bdev->bd_disk->private_data;

	return __nvme_ioctl(ns, cmd, (void __user *)arg);
}

long nvme_ns_chr_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct nvme_ns *ns =
		container_of(file_inode(file)->i_cdev, struct nvme_ns, cdev);

	return __nvme_ioctl(ns, cmd, (void __user *)arg);
}

static int nvme_ns_async_ioctl(struct nvme_ns *ns, struct io_uring_cmd *ioucmd)
{
	struct nvme_uring_cmd *cmd = nvme_uring_cmd(ioucmd);
	int ret;

	switch (cmd->ioctl_cmd) {
	case NVME_IOCTL_IO64_CMD:
		ret = nvme_user_cmd64(ns->ctrl, ns, cmd->argp, ioucmd);
		break;
	default:
		ret = -ENOTTY;
	}

	if (ret >= 0)
		ret = -EIOCBQUEUED;
	return ret;
}

int nvme_ns_chr_async_cmd(struct io_uring_cmd *ioucmd,
		enum io_uring_cmd_flags flags)
{
	struct nvme_ns *ns = container_of(file_inode(ioucmd->file)->i_cdev,
			struct nvme_ns, cdev);

	return nvme_ns_async_ioctl(ns, ioucmd);
}

int nvme_iopoll(struct kiocb *kiocb, struct io_comp_batch *iob,
		unsigned int flags)
{
	struct bio *bio = NULL;
	struct nvme_ns *ns = NULL;
	struct request_queue *q = NULL;
	int ret = 0;

	rcu_read_lock();
	bio = READ_ONCE(kiocb->private);
	ns = container_of(file_inode(kiocb->ki_filp)->i_cdev, struct nvme_ns,
			  cdev);
	q = ns->queue;

	/* bio and driver_cb are a part of the same union type in io_uring_cmd
	 * struct. When there are no poll queues, driver_cb is used for IRQ cb
	 * but polling is performed from the io_uring side. To avoid unnecessary
	 * polling, a check is added to see if it is a polled queue and return 0
	 * if it is not.
	 */
	if ((test_bit(QUEUE_FLAG_POLL, &q->queue_flags)) && bio && bio->bi_bdev)
		ret = bio_poll(bio, iob, flags);
	rcu_read_unlock();
	return ret;
}

#ifdef CONFIG_NVME_MULTIPATH
static int nvme_ns_head_ctrl_ioctl(struct nvme_ns *ns, unsigned int cmd,
		void __user *argp, struct nvme_ns_head *head, int srcu_idx)
	__releases(&head->srcu)
{
	struct nvme_ctrl *ctrl = ns->ctrl;
	int ret;

	nvme_get_ctrl(ns->ctrl);
	srcu_read_unlock(&head->srcu, srcu_idx);
	ret = nvme_ctrl_ioctl(ns->ctrl, cmd, argp);

	nvme_put_ctrl(ctrl);
	return ret;
}

int nvme_ns_head_ioctl(struct block_device *bdev, fmode_t mode,
		unsigned int cmd, unsigned long arg)
{
	struct nvme_ns_head *head = bdev->bd_disk->private_data;
	void __user *argp = (void __user *)arg;
	struct nvme_ns *ns;
	int srcu_idx, ret = -EWOULDBLOCK;

	srcu_idx = srcu_read_lock(&head->srcu);
	ns = nvme_find_path(head);
	if (!ns)
		goto out_unlock;

	/*
	 * Handle ioctls that apply to the controller instead of the namespace
	 * seperately and drop the ns SRCU reference early.  This avoids a
	 * deadlock when deleting namespaces using the passthrough interface.
	 */
	if (is_ctrl_ioctl(cmd))
		return nvme_ns_head_ctrl_ioctl(ns, cmd, argp, head, srcu_idx);

	ret = nvme_ns_ioctl(ns, cmd, argp);
out_unlock:
	srcu_read_unlock(&head->srcu, srcu_idx);
	return ret;
}

int nvme_ns_head_chr_async_cmd(struct io_uring_cmd *ioucmd,
		enum io_uring_cmd_flags flags)
{
	struct cdev *cdev = file_inode(ioucmd->file)->i_cdev;
	struct nvme_ns_head *head = container_of(cdev, struct nvme_ns_head, cdev);
	int srcu_idx = srcu_read_lock(&head->srcu);
	struct nvme_ns *ns = nvme_find_path(head);
	int ret = -EWOULDBLOCK;

	if (ns)
		ret = nvme_ns_async_ioctl(ns, ioucmd);
	srcu_read_unlock(&head->srcu, srcu_idx);
	return ret;
}

long nvme_ns_head_chr_ioctl(struct file *file, unsigned int cmd,
		unsigned long arg)
{
	struct cdev *cdev = file_inode(file)->i_cdev;
	struct nvme_ns_head *head =
		container_of(cdev, struct nvme_ns_head, cdev);
	void __user *argp = (void __user *)arg;
	struct nvme_ns *ns;
	int srcu_idx, ret = -EWOULDBLOCK;

	srcu_idx = srcu_read_lock(&head->srcu);
	ns = nvme_find_path(head);
	if (!ns)
		goto out_unlock;

	if (is_ctrl_ioctl(cmd))
		return nvme_ns_head_ctrl_ioctl(ns, cmd, argp, head, srcu_idx);

	ret = nvme_ns_ioctl(ns, cmd, argp);
out_unlock:
	srcu_read_unlock(&head->srcu, srcu_idx);
	return ret;
}

int nvme_ns_head_iopoll(struct kiocb *kiocb, struct io_comp_batch *iob,
			unsigned int flags)
{
	struct bio *bio = NULL;
	struct request_queue *q = NULL;
	struct cdev *cdev = file_inode(kiocb->ki_filp)->i_cdev;
	struct nvme_ns_head *head = container_of(cdev, struct nvme_ns_head, cdev);
	int srcu_idx = srcu_read_lock(&head->srcu);
	struct nvme_ns *ns = nvme_find_path(head);
	int ret = -EWOULDBLOCK;

	if (ns) {
		bio = READ_ONCE(kiocb->private);
		q = ns->queue;
	    /* bio and driver_cb are a part of the same union type in io_uring_cmd
	     * struct. When there are no poll queues, driver_cb is used for IRQ cb
	     * but polling is performed from the io_uring side. To avoid unnecessary
	     * polling, a check is added to see if it is a polled queue and return 0
	     * if it is not.
	     */
		if ((test_bit(QUEUE_FLAG_POLL, &q->queue_flags)) && bio &&
		    bio->bi_bdev)
			ret = bio_poll(bio, iob, flags);
	}

	srcu_read_unlock(&head->srcu, srcu_idx);
	return ret;
}
#endif /* CONFIG_NVME_MULTIPATH */

static int nvme_dev_user_cmd(struct nvme_ctrl *ctrl, void __user *argp)
{
	struct nvme_ns *ns;
	int ret;

	down_read(&ctrl->namespaces_rwsem);
	if (list_empty(&ctrl->namespaces)) {
		ret = -ENOTTY;
		goto out_unlock;
	}

	ns = list_first_entry(&ctrl->namespaces, struct nvme_ns, list);
	if (ns != list_last_entry(&ctrl->namespaces, struct nvme_ns, list)) {
		dev_warn(ctrl->device,
			"NVME_IOCTL_IO_CMD not supported when multiple namespaces present!\n");
		ret = -EINVAL;
		goto out_unlock;
	}

	dev_warn(ctrl->device,
		"using deprecated NVME_IOCTL_IO_CMD ioctl on the char device!\n");
	kref_get(&ns->kref);
	up_read(&ctrl->namespaces_rwsem);

	ret = nvme_user_cmd(ctrl, ns, argp);
	nvme_put_ns(ns);
	return ret;

out_unlock:
	up_read(&ctrl->namespaces_rwsem);
	return ret;
}

long nvme_dev_ioctl(struct file *file, unsigned int cmd,
		unsigned long arg)
{
	struct nvme_ctrl *ctrl = file->private_data;
	void __user *argp = (void __user *)arg;

	switch (cmd) {
	case NVME_IOCTL_ADMIN_CMD:
		return nvme_user_cmd(ctrl, NULL, argp);
	case NVME_IOCTL_ADMIN64_CMD:
		return nvme_user_cmd64(ctrl, NULL, argp, NULL);
	case NVME_IOCTL_IO_CMD:
		return nvme_dev_user_cmd(ctrl, argp);
	case NVME_IOCTL_RESET:
		dev_warn(ctrl->device, "resetting controller\n");
		return nvme_reset_ctrl_sync(ctrl);
	case NVME_IOCTL_SUBSYS_RESET:
		return nvme_reset_subsystem(ctrl);
	case NVME_IOCTL_RESCAN:
		nvme_queue_scan(ctrl);
		return 0;
	default:
		return -ENOTTY;
	}
}
