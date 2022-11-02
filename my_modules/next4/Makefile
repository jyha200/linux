# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the linux next4-filesystem routines.
#

obj-m += next4.o

next4-objs	:= balloc.o bitmap.o block_validity.o dir.o next4_njbd2.o extents.o \
		extents_status.o file.o fsmap.o fsync.o hash.o ialloc.o \
		indirect.o inline.o inode.o ioctl.o mballoc.o migrate.o \
		mmp.o move_extent.o namei.o page-io.o readpage.o resize.o \
		super.o symlink.o sysfs.o xattr.o xattr_hurd.o xattr_trusted.o \
		xattr_user.o fast_commit.o orphan.o

next4-$(CONFIG_EXT4_FS_POSIX_ACL)	+= acl.o
next4-$(CONFIG_EXT4_FS_SECURITY)		+= xattr_security.o
next4-inode-test-objs			+= inode-test.o
obj-$(CONFIG_EXT4_KUNIT_TESTS)		+= next4-inode-test.o
next4-$(CONFIG_FS_VERITY)		+= verity.o
next4-$(CONFIG_FS_ENCRYPTION)		+= crypto.o


KDIR := /lib/modules/$(shell uname -r)/build
PWD :=$(shell pwd)

default :
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean :
	rm *.mod.*
	rm *.ko
	rm *.o
