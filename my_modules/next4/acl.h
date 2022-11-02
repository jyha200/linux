// SPDX-License-Identifier: GPL-2.0
/*
  File: fs/next4/acl.h

  (C) 2001 Andreas Gruenbacher, <a.gruenbacher@computer.org>
*/

#include <linux/posix_acl_xattr.h>

#define NEXT4_ACL_VERSION	0x0001

typedef struct {
	__le16		e_tag;
	__le16		e_perm;
	__le32		e_id;
} next4_acl_entry;

typedef struct {
	__le16		e_tag;
	__le16		e_perm;
} next4_acl_entry_short;

typedef struct {
	__le32		a_version;
} next4_acl_header;

static inline size_t next4_acl_size(int count)
{
	if (count <= 4) {
		return sizeof(next4_acl_header) +
		       count * sizeof(next4_acl_entry_short);
	} else {
		return sizeof(next4_acl_header) +
		       4 * sizeof(next4_acl_entry_short) +
		       (count - 4) * sizeof(next4_acl_entry);
	}
}

static inline int next4_acl_count(size_t size)
{
	ssize_t s;
	size -= sizeof(next4_acl_header);
	s = size - 4 * sizeof(next4_acl_entry_short);
	if (s < 0) {
		if (size % sizeof(next4_acl_entry_short))
			return -1;
		return size / sizeof(next4_acl_entry_short);
	} else {
		if (s % sizeof(next4_acl_entry))
			return -1;
		return s / sizeof(next4_acl_entry) + 4;
	}
}

#ifdef CONFIG_EXT4_FS_POSIX_ACL

/* acl.c */
struct posix_acl *next4_get_acl(struct inode *inode, int type, bool rcu);
int next4_set_acl(struct user_namespace *mnt_userns, struct inode *inode,
		 struct posix_acl *acl, int type);
extern int next4_init_acl(handle_t *, struct inode *, struct inode *);

#else  /* CONFIG_NEXT4_FS_POSIX_ACL */
#include <linux/sched.h>
#define next4_get_acl NULL
#define next4_set_acl NULL

static inline int
next4_init_acl(handle_t *handle, struct inode *inode, struct inode *dir)
{
	return 0;
}
#endif  /* CONFIG_NEXT4_FS_POSIX_ACL */

