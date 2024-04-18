# SPDX-License-Identifier: GPL-2.0
obj-m += f3fs.o

f3fs-y		:= dir.o file.o inode.o namei.o hash.o super.o inline.o
f3fs-y		+= checkpoint.o gc.o data.o node.o segment.o recovery.o
f3fs-y		+= shrinker.o extent_cache.o sysfs.o lockfree_list.o calclock.o
#f3fs-$(CONFIG_F2FS_STAT_FS) += debug.o
#f3fs-$(CONFIG_F2FS_FS_XATTR) += xattr.o
#f3fs-$(CONFIG_F2FS_FS_POSIX_ACL) += acl.o
f3fs-$(CONFIG_FS_VERITY) += verity.o
#f3fs-$(CONFIG_F2FS_FS_COMPRESSION) += compress.o
#f3fs-$(CONFIG_F2FS_IOSTAT) += iostat.o

default:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean

lock_test: rm_lock_test
	$(CC) test_range_lock.c lockfree_list.c -o lock_test -lpthread $(shell pkg-config --cflags --libs glib-2.0) -g

rm_lock_test:
	rm -f lock_test
