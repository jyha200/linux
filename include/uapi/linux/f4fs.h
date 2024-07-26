/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#ifndef _UAPI_LINUX_F4FS_H
#define _UAPI_LINUX_F4FS_H
#include <linux/types.h>
#include <linux/ioctl.h>

/*
 * f4fs-specific ioctl commands
 */
#define F4FS_IOCTL_MAGIC		0xf5
#define F4FS_IOC_START_ATOMIC_WRITE	_IO(F4FS_IOCTL_MAGIC, 1)
#define F4FS_IOC_COMMIT_ATOMIC_WRITE	_IO(F4FS_IOCTL_MAGIC, 2)
#define F4FS_IOC_START_VOLATILE_WRITE	_IO(F4FS_IOCTL_MAGIC, 3)
#define F4FS_IOC_RELEASE_VOLATILE_WRITE	_IO(F4FS_IOCTL_MAGIC, 4)
#define F4FS_IOC_ABORT_ATOMIC_WRITE	_IO(F4FS_IOCTL_MAGIC, 5)
#define F4FS_IOC_GARBAGE_COLLECT	_IOW(F4FS_IOCTL_MAGIC, 6, __u32)
#define F4FS_IOC_WRITE_CHECKPOINT	_IO(F4FS_IOCTL_MAGIC, 7)
#define F4FS_IOC_DEFRAGMENT		_IOWR(F4FS_IOCTL_MAGIC, 8,	\
						struct f4fs_defragment)
#define F4FS_IOC_MOVE_RANGE		_IOWR(F4FS_IOCTL_MAGIC, 9,	\
						struct f4fs_move_range)
#define F4FS_IOC_FLUSH_DEVICE		_IOW(F4FS_IOCTL_MAGIC, 10,	\
						struct f4fs_flush_device)
#define F4FS_IOC_GARBAGE_COLLECT_RANGE	_IOW(F4FS_IOCTL_MAGIC, 11,	\
						struct f4fs_gc_range)
#define F4FS_IOC_GET_FEATURES		_IOR(F4FS_IOCTL_MAGIC, 12, __u32)
#define F4FS_IOC_SET_PIN_FILE		_IOW(F4FS_IOCTL_MAGIC, 13, __u32)
#define F4FS_IOC_GET_PIN_FILE		_IOR(F4FS_IOCTL_MAGIC, 14, __u32)
#define F4FS_IOC_PRECACHE_EXTENTS	_IO(F4FS_IOCTL_MAGIC, 15)
#define F4FS_IOC_RESIZE_FS		_IOW(F4FS_IOCTL_MAGIC, 16, __u64)
#define F4FS_IOC_GET_COMPRESS_BLOCKS	_IOR(F4FS_IOCTL_MAGIC, 17, __u64)
#define F4FS_IOC_RELEASE_COMPRESS_BLOCKS				\
					_IOR(F4FS_IOCTL_MAGIC, 18, __u64)
#define F4FS_IOC_RESERVE_COMPRESS_BLOCKS				\
					_IOR(F4FS_IOCTL_MAGIC, 19, __u64)
#define F4FS_IOC_SEC_TRIM_FILE		_IOW(F4FS_IOCTL_MAGIC, 20,	\
						struct f4fs_sectrim_range)
#define F4FS_IOC_GET_COMPRESS_OPTION	_IOR(F4FS_IOCTL_MAGIC, 21,	\
						struct f4fs_comp_option)
#define F4FS_IOC_SET_COMPRESS_OPTION	_IOW(F4FS_IOCTL_MAGIC, 22,	\
						struct f4fs_comp_option)
#define F4FS_IOC_DECOMPRESS_FILE	_IO(F4FS_IOCTL_MAGIC, 23)
#define F4FS_IOC_COMPRESS_FILE		_IO(F4FS_IOCTL_MAGIC, 24)

/*
 * should be same as XFS_IOC_GOINGDOWN.
 * Flags for going down operation used by FS_IOC_GOINGDOWN
 */
#define F4FS_IOC_SHUTDOWN	_IOR('X', 125, __u32)	/* Shutdown */
#define F4FS_GOING_DOWN_FULLSYNC	0x0	/* going down with full sync */
#define F4FS_GOING_DOWN_METASYNC	0x1	/* going down with metadata */
#define F4FS_GOING_DOWN_NOSYNC		0x2	/* going down */
#define F4FS_GOING_DOWN_METAFLUSH	0x3	/* going down with meta flush */
#define F4FS_GOING_DOWN_NEED_FSCK	0x4	/* going down to trigger fsck */

/*
 * Flags used by F4FS_IOC_SEC_TRIM_FILE
 */
#define F4FS_TRIM_FILE_DISCARD		0x1	/* send discard command */
#define F4FS_TRIM_FILE_ZEROOUT		0x2	/* zero out */
#define F4FS_TRIM_FILE_MASK		0x3

struct f4fs_gc_range {
	__u32 sync;
	__u64 start;
	__u64 len;
};

struct f4fs_defragment {
	__u64 start;
	__u64 len;
};

struct f4fs_move_range {
	__u32 dst_fd;		/* destination fd */
	__u64 pos_in;		/* start position in src_fd */
	__u64 pos_out;		/* start position in dst_fd */
	__u64 len;		/* size to move */
};

struct f4fs_flush_device {
	__u32 dev_num;		/* device number to flush */
	__u32 segments;		/* # of segments to flush */
};

struct f4fs_sectrim_range {
	__u64 start;
	__u64 len;
	__u64 flags;
};

struct f4fs_comp_option {
	__u8 algorithm;
	__u8 log_cluster_size;
};

#endif /* _UAPI_LINUX_F4FS_H */
