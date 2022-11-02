// SPDX-License-Identifier: GPL-2.0
/*
 * linux/fs/next4/xattr_user.c
 * Handler for extended user attributes.
 *
 * Copyright (C) 2001 by Andreas Gruenbacher, <a.gruenbacher@computer.org>
 */

#include <linux/string.h>
#include <linux/fs.h>
#include "next4_njbd2.h"
#include "next4.h"
#include "xattr.h"

static bool
next4_xattr_user_list(struct dentry *dentry)
{
	return test_opt(dentry->d_sb, XATTR_USER);
}

static int
next4_xattr_user_get(const struct xattr_handler *handler,
		    struct dentry *unused, struct inode *inode,
		    const char *name, void *buffer, size_t size)
{
	if (!test_opt(inode->i_sb, XATTR_USER))
		return -EOPNOTSUPP;
	return next4_xattr_get(inode, NEXT4_XATTR_INDEX_USER,
			      name, buffer, size);
}

static int
next4_xattr_user_set(const struct xattr_handler *handler,
		    struct user_namespace *mnt_userns,
		    struct dentry *unused, struct inode *inode,
		    const char *name, const void *value,
		    size_t size, int flags)
{
	if (!test_opt(inode->i_sb, XATTR_USER))
		return -EOPNOTSUPP;
	return next4_xattr_set(inode, NEXT4_XATTR_INDEX_USER,
			      name, value, size, flags);
}

const struct xattr_handler next4_xattr_user_handler = {
	.prefix	= XATTR_USER_PREFIX,
	.list	= next4_xattr_user_list,
	.get	= next4_xattr_user_get,
	.set	= next4_xattr_user_set,
};
