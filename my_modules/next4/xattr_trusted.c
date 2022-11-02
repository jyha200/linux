// SPDX-License-Identifier: GPL-2.0
/*
 * linux/fs/next4/xattr_trusted.c
 * Handler for trusted extended attributes.
 *
 * Copyright (C) 2003 by Andreas Gruenbacher, <a.gruenbacher@computer.org>
 */

#include <linux/string.h>
#include <linux/capability.h>
#include <linux/fs.h>
#include "next4_njbd2.h"
#include "next4.h"
#include "xattr.h"

static bool
next4_xattr_trusted_list(struct dentry *dentry)
{
	return capable(CAP_SYS_ADMIN);
}

static int
next4_xattr_trusted_get(const struct xattr_handler *handler,
		       struct dentry *unused, struct inode *inode,
		       const char *name, void *buffer, size_t size)
{
	return next4_xattr_get(inode, NEXT4_XATTR_INDEX_TRUSTED,
			      name, buffer, size);
}

static int
next4_xattr_trusted_set(const struct xattr_handler *handler,
		       struct user_namespace *mnt_userns,
		       struct dentry *unused, struct inode *inode,
		       const char *name, const void *value,
		       size_t size, int flags)
{
	return next4_xattr_set(inode, NEXT4_XATTR_INDEX_TRUSTED,
			      name, value, size, flags);
}

const struct xattr_handler next4_xattr_trusted_handler = {
	.prefix	= XATTR_TRUSTED_PREFIX,
	.list	= next4_xattr_trusted_list,
	.get	= next4_xattr_trusted_get,
	.set	= next4_xattr_trusted_set,
};
