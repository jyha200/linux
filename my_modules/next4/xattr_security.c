// SPDX-License-Identifier: GPL-2.0
/*
 * linux/fs/next4/xattr_security.c
 * Handler for storing security labels as extended attributes.
 */

#include <linux/string.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/slab.h>
#include "next4_njbd2.h"
#include "next4.h"
#include "xattr.h"

static int
next4_xattr_security_get(const struct xattr_handler *handler,
			struct dentry *unused, struct inode *inode,
			const char *name, void *buffer, size_t size)
{
	return next4_xattr_get(inode, NEXT4_XATTR_INDEX_SECURITY,
			      name, buffer, size);
}

static int
next4_xattr_security_set(const struct xattr_handler *handler,
			struct user_namespace *mnt_userns,
			struct dentry *unused, struct inode *inode,
			const char *name, const void *value,
			size_t size, int flags)
{
	return next4_xattr_set(inode, NEXT4_XATTR_INDEX_SECURITY,
			      name, value, size, flags);
}

static int
next4_initxattrs(struct inode *inode, const struct xattr *xattr_array,
		void *fs_info)
{
	const struct xattr *xattr;
	handle_t *handle = fs_info;
	int err = 0;

	for (xattr = xattr_array; xattr->name != NULL; xattr++) {
		err = next4_xattr_set_handle(handle, inode,
					    NEXT4_XATTR_INDEX_SECURITY,
					    xattr->name, xattr->value,
					    xattr->value_len, XATTR_CREATE);
		if (err < 0)
			break;
	}
	return err;
}

int
next4_init_security(handle_t *handle, struct inode *inode, struct inode *dir,
		   const struct qstr *qstr)
{
	return security_inode_init_security(inode, dir, qstr,
					    &next4_initxattrs, handle);
}

const struct xattr_handler next4_xattr_security_handler = {
	.prefix	= XATTR_SECURITY_PREFIX,
	.get	= next4_xattr_security_get,
	.set	= next4_xattr_security_set,
};
