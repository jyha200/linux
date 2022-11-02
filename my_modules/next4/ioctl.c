// SPDX-License-Identifier: GPL-2.0
/*
 * linux/fs/next4/ioctl.c
 *
 * Copyright (C) 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 */

#include <linux/fs.h>
#include <linux/capability.h>
#include <linux/time.h>
#include <linux/compat.h>
#include <linux/mount.h>
#include <linux/file.h>
#include <linux/quotaops.h>
#include <linux/random.h>
#include <linux/uaccess.h>
#include <linux/delay.h>
#include <linux/iversion.h>
#include <linux/fileattr.h>
#include <linux/uuid.h>
#include "next4_njbd2.h"
#include "next4.h"
#include <linux/fsmap.h>
#include "fsmap.h"
#include <trace/events/next4.h>

typedef void next4_update_sb_callback(struct next4_super_block *es,
				       const void *arg);

/*
 * Superblock modification callback function for changing file system
 * label
 */
static void next4_sb_setlabel(struct next4_super_block *es, const void *arg)
{
	/* Sanity check, this should never happen */
	BUILD_BUG_ON(sizeof(es->s_volume_name) < NEXT4_LABEL_MAX);

	memcpy(es->s_volume_name, (char *)arg, NEXT4_LABEL_MAX);
}

/*
 * Superblock modification callback function for changing file system
 * UUID.
 */
static void next4_sb_setuuid(struct next4_super_block *es, const void *arg)
{
	memcpy(es->s_uuid, (__u8 *)arg, UUID_SIZE);
}

static
int next4_update_primary_sb(struct super_block *sb, handle_t *handle,
			   next4_update_sb_callback func,
			   const void *arg)
{
	int err = 0;
	struct next4_sb_info *sbi = NEXT4_SB(sb);
	struct buffer_head *bh = sbi->s_sbh;
	struct next4_super_block *es = sbi->s_es;

	trace_next4_update_sb(sb, bh->b_blocknr, 1);

	BUFFER_TRACE(bh, "get_write_access");
	err = next4_journal_get_write_access(handle, sb,
					    bh,
					    NEXT4_JTR_NONE);
	if (err)
		goto out_err;

	lock_buffer(bh);
	func(es, arg);
	next4_superblock_csum_set(sb);
	unlock_buffer(bh);

	if (buffer_write_io_error(bh) || !buffer_uptodate(bh)) {
		next4_msg(sbi->s_sb, KERN_ERR, "previous I/O error to "
			 "superblock detected");
		clear_buffer_write_io_error(bh);
		set_buffer_uptodate(bh);
	}

	err = next4_handle_dirty_metadata(handle, NULL, bh);
	if (err)
		goto out_err;
	err = sync_dirty_buffer(bh);
out_err:
	next4_std_error(sb, err);
	return err;
}

/*
 * Update one backup superblock in the group 'grp' using the callback
 * function 'func' and argument 'arg'. If the handle is NULL the
 * modification is not journalled.
 *
 * Returns: 0 when no modification was done (no superblock in the group)
 *	    1 when the modification was successful
 *	   <0 on error
 */
static int next4_update_backup_sb(struct super_block *sb,
				 handle_t *handle, next4_group_t grp,
				 next4_update_sb_callback func, const void *arg)
{
	int err = 0;
	next4_fsblk_t sb_block;
	struct buffer_head *bh;
	unsigned long offset = 0;
	struct next4_super_block *es;

	if (!next4_bg_has_super(sb, grp))
		return 0;

	/*
	 * For the group 0 there is always 1k padding, so we have
	 * either adjust offset, or sb_block depending on blocksize
	 */
	if (grp == 0) {
		sb_block = 1 * NEXT4_MIN_BLOCK_SIZE;
		offset = do_div(sb_block, sb->s_blocksize);
	} else {
		sb_block = next4_group_first_block_no(sb, grp);
		offset = 0;
	}

	trace_next4_update_sb(sb, sb_block, handle ? 1 : 0);

	bh = next4_sb_bread(sb, sb_block, 0);
	if (IS_ERR(bh))
		return PTR_ERR(bh);

	if (handle) {
		BUFFER_TRACE(bh, "get_write_access");
		err = next4_journal_get_write_access(handle, sb,
						    bh,
						    NEXT4_JTR_NONE);
		if (err)
			goto out_bh;
	}

	es = (struct next4_super_block *) (bh->b_data + offset);
	lock_buffer(bh);
	if (next4_has_metadata_csum(sb) &&
	    es->s_checksum != next4_superblock_csum(sb, es)) {
		next4_msg(sb, KERN_ERR, "Invalid checksum for backup "
		"superblock %llu\n", sb_block);
		unlock_buffer(bh);
		err = -EFSBADCRC;
		goto out_bh;
	}
	func(es, arg);
	if (next4_has_metadata_csum(sb))
		es->s_checksum = next4_superblock_csum(sb, es);
	set_buffer_uptodate(bh);
	unlock_buffer(bh);

	if (err)
		goto out_bh;

	if (handle) {
		err = next4_handle_dirty_metadata(handle, NULL, bh);
		if (err)
			goto out_bh;
	} else {
		BUFFER_TRACE(bh, "marking dirty");
		mark_buffer_dirty(bh);
	}
	err = sync_dirty_buffer(bh);

out_bh:
	brelse(bh);
	next4_std_error(sb, err);
	return (err) ? err : 1;
}

/*
 * Update primary and backup superblocks using the provided function
 * func and argument arg.
 *
 * Only the primary superblock and at most two backup superblock
 * modifications are journalled; the rest is modified without journal.
 * This is safe because e2fsck will re-write them if there is a problem,
 * and we're very unlikely to ever need more than two backups.
 */
static
int next4_update_superblocks_fn(struct super_block *sb,
			       next4_update_sb_callback func,
			       const void *arg)
{
	handle_t *handle;
	next4_group_t ngroups;
	unsigned int three = 1;
	unsigned int five = 5;
	unsigned int seven = 7;
	int err = 0, ret, i;
	next4_group_t grp, primary_grp;
	struct next4_sb_info *sbi = NEXT4_SB(sb);

	/*
	 * We can't update superblocks while the online resize is running
	 */
	if (test_and_set_bit_lock(NEXT4_FLAGS_RESIZING,
				  &sbi->s_next4_flags)) {
		next4_msg(sb, KERN_ERR, "Can't modify superblock while"
			 "performing online resize");
		return -EBUSY;
	}

	/*
	 * We're only going to update primary superblock and two
	 * backup superblocks in this transaction.
	 */
	handle = next4_journal_start_sb(sb, NEXT4_HT_MISC, 3);
	if (IS_ERR(handle)) {
		err = PTR_ERR(handle);
		goto out;
	}

	/* Update primary superblock */
	err = next4_update_primary_sb(sb, handle, func, arg);
	if (err) {
		next4_msg(sb, KERN_ERR, "Failed to update primary "
			 "superblock");
		goto out_journal;
	}

	primary_grp = next4_get_group_number(sb, sbi->s_sbh->b_blocknr);
	ngroups = next4_get_groups_count(sb);

	/*
	 * Update backup superblocks. We have to start from group 0
	 * because it might not be where the primary superblock is
	 * if the fs is mounted with -o sb=<backup_sb_block>
	 */
	i = 0;
	grp = 0;
	while (grp < ngroups) {
		/* Skip primary superblock */
		if (grp == primary_grp)
			goto next_grp;

		ret = next4_update_backup_sb(sb, handle, grp, func, arg);
		if (ret < 0) {
			/* Ignore bad checksum; try to update next sb */
			if (ret == -EFSBADCRC)
				goto next_grp;
			err = ret;
			goto out_journal;
		}

		i += ret;
		if (handle && i > 1) {
			/*
			 * We're only journalling primary superblock and
			 * two backup superblocks; the rest is not
			 * journalled.
			 */
			err = next4_journal_stop(handle);
			if (err)
				goto out;
			handle = NULL;
		}
next_grp:
		grp = next4_list_backups(sb, &three, &five, &seven);
	}

out_journal:
	if (handle) {
		ret = next4_journal_stop(handle);
		if (ret && !err)
			err = ret;
	}
out:
	clear_bit_unlock(NEXT4_FLAGS_RESIZING, &sbi->s_next4_flags);
	smp_mb__after_atomic();
	return err ? err : 0;
}

/*
 * Swap memory between @a and @b for @len bytes.
 *
 * @a:          pointer to first memory area
 * @b:          pointer to second memory area
 * @len:        number of bytes to swap
 *
 */
static void memswap(void *a, void *b, size_t len)
{
	unsigned char *ap, *bp;

	ap = (unsigned char *)a;
	bp = (unsigned char *)b;
	while (len-- > 0) {
		swap(*ap, *bp);
		ap++;
		bp++;
	}
}

/*
 * Swap i_data and associated attributes between @inode1 and @inode2.
 * This function is used for the primary swap between inode1 and inode2
 * and also to revert this primary swap in case of errors.
 *
 * Therefore you have to make sure, that calling this method twice
 * will revert all changes.
 *
 * @inode1:     pointer to first inode
 * @inode2:     pointer to second inode
 */
static void swap_inode_data(struct inode *inode1, struct inode *inode2)
{
	loff_t isize;
	struct next4_inode_info *ei1;
	struct next4_inode_info *ei2;
	unsigned long tmp;

	ei1 = NEXT4_I(inode1);
	ei2 = NEXT4_I(inode2);

	swap(inode1->i_version, inode2->i_version);
	swap(inode1->i_atime, inode2->i_atime);
	swap(inode1->i_mtime, inode2->i_mtime);

	memswap(ei1->i_data, ei2->i_data, sizeof(ei1->i_data));
	tmp = ei1->i_flags & NEXT4_FL_SHOULD_SWAP;
	ei1->i_flags = (ei2->i_flags & NEXT4_FL_SHOULD_SWAP) |
		(ei1->i_flags & ~NEXT4_FL_SHOULD_SWAP);
	ei2->i_flags = tmp | (ei2->i_flags & ~NEXT4_FL_SHOULD_SWAP);
	swap(ei1->i_disksize, ei2->i_disksize);
	next4_es_remove_extent(inode1, 0, EXT_MAX_BLOCKS);
	next4_es_remove_extent(inode2, 0, EXT_MAX_BLOCKS);

	isize = i_size_read(inode1);
	i_size_write(inode1, i_size_read(inode2));
	i_size_write(inode2, isize);
}

void next4_reset_inode_seed(struct inode *inode)
{
	struct next4_inode_info *ei = NEXT4_I(inode);
	struct next4_sb_info *sbi = NEXT4_SB(inode->i_sb);
	__le32 inum = cpu_to_le32(inode->i_ino);
	__le32 gen = cpu_to_le32(inode->i_generation);
	__u32 csum;

	if (!next4_has_metadata_csum(inode->i_sb))
		return;

	csum = next4_chksum(sbi, sbi->s_csum_seed, (__u8 *)&inum, sizeof(inum));
	ei->i_csum_seed = next4_chksum(sbi, csum, (__u8 *)&gen, sizeof(gen));
}

/*
 * Swap the information from the given @inode and the inode
 * NEXT4_BOOT_LOADER_INO. It will basically swap i_data and all other
 * important fields of the inodes.
 *
 * @sb:         the super block of the filesystem
 * @mnt_userns:	user namespace of the mount the inode was found from
 * @inode:      the inode to swap with NEXT4_BOOT_LOADER_INO
 *
 */
static long swap_inode_boot_loader(struct super_block *sb,
				struct user_namespace *mnt_userns,
				struct inode *inode)
{
	handle_t *handle;
	int err;
	struct inode *inode_bl;
	struct next4_inode_info *ei_bl;
	qsize_t size, size_bl, diff;
	blkcnt_t blocks;
	unsigned short bytes;

	inode_bl = next4_iget(sb, NEXT4_BOOT_LOADER_INO, NEXT4_IGET_SPECIAL);
	if (IS_ERR(inode_bl))
		return PTR_ERR(inode_bl);
	ei_bl = NEXT4_I(inode_bl);

	/* Protect orig inodes against a truncate and make sure,
	 * that only 1 swap_inode_boot_loader is running. */
	lock_two_nondirectories(inode, inode_bl);

	if (inode->i_nlink != 1 || !S_ISREG(inode->i_mode) ||
	    IS_SWAPFILE(inode) || IS_ENCRYPTED(inode) ||
	    (NEXT4_I(inode)->i_flags & NEXT4_JOURNAL_DATA_FL) ||
	    next4_has_inline_data(inode)) {
		err = -EINVAL;
		goto journal_err_out;
	}

	if (IS_RDONLY(inode) || IS_APPEND(inode) || IS_IMMUTABLE(inode) ||
	    !inode_owner_or_capable(mnt_userns, inode) ||
	    !capable(CAP_SYS_ADMIN)) {
		err = -EPERM;
		goto journal_err_out;
	}

	filemap_invalidate_lock(inode->i_mapping);
	err = filemap_write_and_wait(inode->i_mapping);
	if (err)
		goto err_out;

	err = filemap_write_and_wait(inode_bl->i_mapping);
	if (err)
		goto err_out;

	/* Wait for all existing dio workers */
	inode_dio_wait(inode);
	inode_dio_wait(inode_bl);

	truncate_inode_pages(&inode->i_data, 0);
	truncate_inode_pages(&inode_bl->i_data, 0);

	handle = next4_journal_start(inode_bl, NEXT4_HT_MOVE_EXTENTS, 2);
	if (IS_ERR(handle)) {
		err = -EINVAL;
		goto err_out;
	}
	next4_fc_mark_ineligible(sb, NEXT4_FC_REASON_SWAP_BOOT, handle);

	/* Protect extent tree against block allocations via delalloc */
	next4_double_down_write_data_sem(inode, inode_bl);

	if (inode_bl->i_nlink == 0) {
		/* this inode has never been used as a BOOT_LOADER */
		set_nlink(inode_bl, 1);
		i_uid_write(inode_bl, 0);
		i_gid_write(inode_bl, 0);
		inode_bl->i_flags = 0;
		ei_bl->i_flags = 0;
		inode_set_iversion(inode_bl, 1);
		i_size_write(inode_bl, 0);
		inode_bl->i_mode = S_IFREG;
		if (next4_has_feature_extents(sb)) {
			next4_set_inode_flag(inode_bl, NEXT4_INODE_EXTENTS);
			next4_ext_tree_init(handle, inode_bl);
		} else
			memset(ei_bl->i_data, 0, sizeof(ei_bl->i_data));
	}

	err = dquot_initialize(inode);
	if (err)
		goto err_out1;

	size = (qsize_t)(inode->i_blocks) * (1 << 9) + inode->i_bytes;
	size_bl = (qsize_t)(inode_bl->i_blocks) * (1 << 9) + inode_bl->i_bytes;
	diff = size - size_bl;
	swap_inode_data(inode, inode_bl);

	inode->i_ctime = inode_bl->i_ctime = current_time(inode);

	inode->i_generation = prandom_u32();
	inode_bl->i_generation = prandom_u32();
	next4_reset_inode_seed(inode);
	next4_reset_inode_seed(inode_bl);

	next4_discard_preallocations(inode, 0);

	err = next4_mark_inode_dirty(handle, inode);
	if (err < 0) {
		/* No need to update quota information. */
		next4_warning(inode->i_sb,
			"couldn't mark inode #%lu dirty (err %d)",
			inode->i_ino, err);
		/* Revert all changes: */
		swap_inode_data(inode, inode_bl);
		next4_mark_inode_dirty(handle, inode);
		goto err_out1;
	}

	blocks = inode_bl->i_blocks;
	bytes = inode_bl->i_bytes;
	inode_bl->i_blocks = inode->i_blocks;
	inode_bl->i_bytes = inode->i_bytes;
	err = next4_mark_inode_dirty(handle, inode_bl);
	if (err < 0) {
		/* No need to update quota information. */
		next4_warning(inode_bl->i_sb,
			"couldn't mark inode #%lu dirty (err %d)",
			inode_bl->i_ino, err);
		goto revert;
	}

	/* Bootloader inode should not be counted into quota information. */
	if (diff > 0)
		dquot_free_space(inode, diff);
	else
		err = dquot_alloc_space(inode, -1 * diff);

	if (err < 0) {
revert:
		/* Revert all changes: */
		inode_bl->i_blocks = blocks;
		inode_bl->i_bytes = bytes;
		swap_inode_data(inode, inode_bl);
		next4_mark_inode_dirty(handle, inode);
		next4_mark_inode_dirty(handle, inode_bl);
	}

err_out1:
	next4_journal_stop(handle);
	next4_double_up_write_data_sem(inode, inode_bl);

err_out:
	filemap_invalidate_unlock(inode->i_mapping);
journal_err_out:
	unlock_two_nondirectories(inode, inode_bl);
	iput(inode_bl);
	return err;
}

/*
 * If immutable is set and we are not clearing it, we're not allowed to change
 * anything else in the inode.  Don't error out if we're only trying to set
 * immutable on an immutable file.
 */
static int next4_ioctl_check_immutable(struct inode *inode, __u32 new_projid,
				      unsigned int flags)
{
	struct next4_inode_info *ei = NEXT4_I(inode);
	unsigned int oldflags = ei->i_flags;

	if (!(oldflags & NEXT4_IMMUTABLE_FL) || !(flags & NEXT4_IMMUTABLE_FL))
		return 0;

	if ((oldflags & ~NEXT4_IMMUTABLE_FL) != (flags & ~NEXT4_IMMUTABLE_FL))
		return -EPERM;
	if (next4_has_feature_project(inode->i_sb) &&
	    __kprojid_val(ei->i_projid) != new_projid)
		return -EPERM;

	return 0;
}

static void next4_dax_dontcache(struct inode *inode, unsigned int flags)
{
	struct next4_inode_info *ei = NEXT4_I(inode);

	if (S_ISDIR(inode->i_mode))
		return;

	if (test_opt2(inode->i_sb, DAX_NEVER) ||
	    test_opt(inode->i_sb, DAX_ALWAYS))
		return;

	if ((ei->i_flags ^ flags) & NEXT4_DAX_FL)
		d_mark_dontcache(inode);
}

static bool dax_compatible(struct inode *inode, unsigned int oldflags,
			   unsigned int flags)
{
	/* Allow the DAX flag to be changed on inline directories */
	if (S_ISDIR(inode->i_mode)) {
		flags &= ~NEXT4_INLINE_DATA_FL;
		oldflags &= ~NEXT4_INLINE_DATA_FL;
	}

	if (flags & NEXT4_DAX_FL) {
		if ((oldflags & NEXT4_DAX_MUT_EXCL) ||
		     next4_test_inode_state(inode,
					  NEXT4_STATE_VERITY_IN_PROGRESS)) {
			return false;
		}
	}

	if ((flags & NEXT4_DAX_MUT_EXCL) && (oldflags & NEXT4_DAX_FL))
			return false;

	return true;
}

static int next4_ioctl_setflags(struct inode *inode,
			       unsigned int flags)
{
	struct next4_inode_info *ei = NEXT4_I(inode);
	handle_t *handle = NULL;
	int err = -EPERM, migrate = 0;
	struct next4_iloc iloc;
	unsigned int oldflags, mask, i;
	struct super_block *sb = inode->i_sb;

	/* Is it quota file? Do not allow user to mess with it */
	if (next4_is_quota_file(inode))
		goto flags_out;

	oldflags = ei->i_flags;
	/*
	 * The JOURNAL_DATA flag can only be changed by
	 * the relevant capability.
	 */
	if ((flags ^ oldflags) & (NEXT4_JOURNAL_DATA_FL)) {
		if (!capable(CAP_SYS_RESOURCE))
			goto flags_out;
	}

	if (!dax_compatible(inode, oldflags, flags)) {
		err = -EOPNOTSUPP;
		goto flags_out;
	}

	if ((flags ^ oldflags) & NEXT4_EXTENTS_FL)
		migrate = 1;

	if ((flags ^ oldflags) & NEXT4_CASEFOLD_FL) {
		if (!next4_has_feature_casefold(sb)) {
			err = -EOPNOTSUPP;
			goto flags_out;
		}

		if (!S_ISDIR(inode->i_mode)) {
			err = -ENOTDIR;
			goto flags_out;
		}

		if (!next4_empty_dir(inode)) {
			err = -ENOTEMPTY;
			goto flags_out;
		}
	}

	/*
	 * Wait for all pending directio and then flush all the dirty pages
	 * for this file.  The flush marks all the pages readonly, so any
	 * subsequent attempt to write to the file (particularly mmap pages)
	 * will come through the filesystem and fail.
	 */
	if (S_ISREG(inode->i_mode) && !IS_IMMUTABLE(inode) &&
	    (flags & NEXT4_IMMUTABLE_FL)) {
		inode_dio_wait(inode);
		err = filemap_write_and_wait(inode->i_mapping);
		if (err)
			goto flags_out;
	}

	handle = next4_journal_start(inode, NEXT4_HT_INODE, 1);
	if (IS_ERR(handle)) {
		err = PTR_ERR(handle);
		goto flags_out;
	}
	if (IS_SYNC(inode))
		next4_handle_sync(handle);
	err = next4_reserve_inode_write(handle, inode, &iloc);
	if (err)
		goto flags_err;

	next4_dax_dontcache(inode, flags);

	for (i = 0, mask = 1; i < 32; i++, mask <<= 1) {
		if (!(mask & NEXT4_FL_USER_MODIFIABLE))
			continue;
		/* These flags get special treatment later */
		if (mask == NEXT4_JOURNAL_DATA_FL || mask == NEXT4_EXTENTS_FL)
			continue;
		if (mask & flags)
			next4_set_inode_flag(inode, i);
		else
			next4_clear_inode_flag(inode, i);
	}

	next4_set_inode_flags(inode, false);

	inode->i_ctime = current_time(inode);

	err = next4_mark_iloc_dirty(handle, inode, &iloc);
flags_err:
	next4_journal_stop(handle);
	if (err)
		goto flags_out;

	if ((flags ^ oldflags) & (NEXT4_JOURNAL_DATA_FL)) {
		/*
		 * Changes to the journaling mode can cause unsafe changes to
		 * S_DAX if the inode is DAX
		 */
		if (IS_DAX(inode)) {
			err = -EBUSY;
			goto flags_out;
		}

		err = next4_change_inode_journal_flag(inode,
						     flags & NEXT4_JOURNAL_DATA_FL);
		if (err)
			goto flags_out;
	}
	if (migrate) {
		if (flags & NEXT4_EXTENTS_FL)
			err = next4_ext_migrate(inode);
		else
			err = next4_ind_migrate(inode);
	}

flags_out:
	return err;
}

#ifdef CONFIG_QUOTA
static int next4_ioctl_setproject(struct inode *inode, __u32 projid)
{
	struct super_block *sb = inode->i_sb;
	struct next4_inode_info *ei = NEXT4_I(inode);
	int err, rc;
	handle_t *handle;
	kprojid_t kprojid;
	struct next4_iloc iloc;
	struct next4_inode *raw_inode;
	struct dquot *transfer_to[MAXQUOTAS] = { };

	if (!next4_has_feature_project(sb)) {
		if (projid != NEXT4_DEF_PROJID)
			return -EOPNOTSUPP;
		else
			return 0;
	}

	if (NEXT4_INODE_SIZE(sb) <= NEXT4_GOOD_OLD_INODE_SIZE)
		return -EOPNOTSUPP;

	kprojid = make_kprojid(&init_user_ns, (projid_t)projid);

	if (projid_eq(kprojid, NEXT4_I(inode)->i_projid))
		return 0;

	err = -EPERM;
	/* Is it quota file? Do not allow user to mess with it */
	if (next4_is_quota_file(inode))
		return err;

	err = next4_get_inode_loc(inode, &iloc);
	if (err)
		return err;

	raw_inode = next4_raw_inode(&iloc);
	if (!NEXT4_FITS_IN_INODE(raw_inode, ei, i_projid)) {
		err = next4_expand_extra_isize(inode,
					      NEXT4_SB(sb)->s_want_extra_isize,
					      &iloc);
		if (err)
			return err;
	} else {
		brelse(iloc.bh);
	}

	err = dquot_initialize(inode);
	if (err)
		return err;

	handle = next4_journal_start(inode, NEXT4_HT_QUOTA,
		NEXT4_QUOTA_INIT_BLOCKS(sb) +
		NEXT4_QUOTA_DEL_BLOCKS(sb) + 3);
	if (IS_ERR(handle))
		return PTR_ERR(handle);

	err = next4_reserve_inode_write(handle, inode, &iloc);
	if (err)
		goto out_stop;

	transfer_to[PRJQUOTA] = dqget(sb, make_kqid_projid(kprojid));
	if (!IS_ERR(transfer_to[PRJQUOTA])) {

		/* __dquot_transfer() calls back next4_get_inode_usage() which
		 * counts xattr inode references.
		 */
		down_read(&NEXT4_I(inode)->xattr_sem);
		err = __dquot_transfer(inode, transfer_to);
		up_read(&NEXT4_I(inode)->xattr_sem);
		dqput(transfer_to[PRJQUOTA]);
		if (err)
			goto out_dirty;
	}

	NEXT4_I(inode)->i_projid = kprojid;
	inode->i_ctime = current_time(inode);
out_dirty:
	rc = next4_mark_iloc_dirty(handle, inode, &iloc);
	if (!err)
		err = rc;
out_stop:
	next4_journal_stop(handle);
	return err;
}
#else
static int next4_ioctl_setproject(struct inode *inode, __u32 projid)
{
	if (projid != NEXT4_DEF_PROJID)
		return -EOPNOTSUPP;
	return 0;
}
#endif

static int next4_shutdown(struct super_block *sb, unsigned long arg)
{
	struct next4_sb_info *sbi = NEXT4_SB(sb);
	__u32 flags;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (get_user(flags, (__u32 __user *)arg))
		return -EFAULT;

	if (flags > NEXT4_GOING_FLAGS_NOLOGFLUSH)
		return -EINVAL;

	if (next4_forced_shutdown(sbi))
		return 0;

	next4_msg(sb, KERN_ALERT, "shut down requested (%d)", flags);
	trace_next4_shutdown(sb, flags);

	switch (flags) {
	case NEXT4_GOING_FLAGS_DEFAULT:
		freeze_bdev(sb->s_bdev);
		set_bit(NEXT4_FLAGS_SHUTDOWN, &sbi->s_next4_flags);
		thaw_bdev(sb->s_bdev);
		break;
	case NEXT4_GOING_FLAGS_LOGFLUSH:
		set_bit(NEXT4_FLAGS_SHUTDOWN, &sbi->s_next4_flags);
		if (sbi->s_journal && !is_journal_aborted(sbi->s_journal)) {
			(void) next4_force_commit(sb);
			njbd2_journal_abort(sbi->s_journal, -ESHUTDOWN);
		}
		break;
	case NEXT4_GOING_FLAGS_NOLOGFLUSH:
		set_bit(NEXT4_FLAGS_SHUTDOWN, &sbi->s_next4_flags);
		if (sbi->s_journal && !is_journal_aborted(sbi->s_journal))
			njbd2_journal_abort(sbi->s_journal, -ESHUTDOWN);
		break;
	default:
		return -EINVAL;
	}
	clear_opt(sb, DISCARD);
	return 0;
}

struct getfsmap_info {
	struct super_block	*gi_sb;
	struct fsmap_head __user *gi_data;
	unsigned int		gi_idx;
	__u32			gi_last_flags;
};

static int next4_getfsmap_format(struct next4_fsmap *xfm, void *priv)
{
	struct getfsmap_info *info = priv;
	struct fsmap fm;

	trace_next4_getfsmap_mapping(info->gi_sb, xfm);

	info->gi_last_flags = xfm->fmr_flags;
	next4_fsmap_from_internal(info->gi_sb, &fm, xfm);
	if (copy_to_user(&info->gi_data->fmh_recs[info->gi_idx++], &fm,
			sizeof(struct fsmap)))
		return -EFAULT;

	return 0;
}

static int next4_ioc_getfsmap(struct super_block *sb,
			     struct fsmap_head __user *arg)
{
	struct getfsmap_info info = { NULL };
	struct next4_fsmap_head xhead = {0};
	struct fsmap_head head;
	bool aborted = false;
	int error;

	if (copy_from_user(&head, arg, sizeof(struct fsmap_head)))
		return -EFAULT;
	if (memchr_inv(head.fmh_reserved, 0, sizeof(head.fmh_reserved)) ||
	    memchr_inv(head.fmh_keys[0].fmr_reserved, 0,
		       sizeof(head.fmh_keys[0].fmr_reserved)) ||
	    memchr_inv(head.fmh_keys[1].fmr_reserved, 0,
		       sizeof(head.fmh_keys[1].fmr_reserved)))
		return -EINVAL;
	/*
	 * next4 doesn't report file extents at all, so the only valid
	 * file offsets are the magic ones (all zeroes or all ones).
	 */
	if (head.fmh_keys[0].fmr_offset ||
	    (head.fmh_keys[1].fmr_offset != 0 &&
	     head.fmh_keys[1].fmr_offset != -1ULL))
		return -EINVAL;

	xhead.fmh_iflags = head.fmh_iflags;
	xhead.fmh_count = head.fmh_count;
	next4_fsmap_to_internal(sb, &xhead.fmh_keys[0], &head.fmh_keys[0]);
	next4_fsmap_to_internal(sb, &xhead.fmh_keys[1], &head.fmh_keys[1]);

	trace_next4_getfsmap_low_key(sb, &xhead.fmh_keys[0]);
	trace_next4_getfsmap_high_key(sb, &xhead.fmh_keys[1]);

	info.gi_sb = sb;
	info.gi_data = arg;
	error = next4_getfsmap(sb, &xhead, next4_getfsmap_format, &info);
	if (error == NEXT4_QUERY_RANGE_ABORT)
		aborted = true;
	else if (error)
		return error;

	/* If we didn't abort, set the "last" flag in the last fmx */
	if (!aborted && info.gi_idx) {
		info.gi_last_flags |= FMR_OF_LAST;
		if (copy_to_user(&info.gi_data->fmh_recs[info.gi_idx - 1].fmr_flags,
				 &info.gi_last_flags,
				 sizeof(info.gi_last_flags)))
			return -EFAULT;
	}

	/* copy back header */
	head.fmh_entries = xhead.fmh_entries;
	head.fmh_oflags = xhead.fmh_oflags;
	if (copy_to_user(arg, &head, sizeof(struct fsmap_head)))
		return -EFAULT;

	return 0;
}

static long next4_ioctl_group_add(struct file *file,
				 struct next4_new_group_data *input)
{
	struct super_block *sb = file_inode(file)->i_sb;
	int err, err2=0;

	err = next4_resize_begin(sb);
	if (err)
		return err;

	if (next4_has_feature_bigalloc(sb)) {
		next4_msg(sb, KERN_ERR,
			 "Online resizing not supported with bigalloc");
		err = -EOPNOTSUPP;
		goto group_add_out;
	}

	err = mnt_want_write_file(file);
	if (err)
		goto group_add_out;

	err = next4_group_add(sb, input);
	if (NEXT4_SB(sb)->s_journal) {
		njbd2_journal_lock_updates(NEXT4_SB(sb)->s_journal);
		err2 = njbd2_journal_flush(NEXT4_SB(sb)->s_journal, 0);
		njbd2_journal_unlock_updates(NEXT4_SB(sb)->s_journal);
	}
	if (err == 0)
		err = err2;
	mnt_drop_write_file(file);
	if (!err && next4_has_group_desc_csum(sb) &&
	    test_opt(sb, INIT_INODE_TABLE))
		err = next4_register_li_request(sb, input->group);
group_add_out:
	err2 = next4_resize_end(sb, false);
	if (err == 0)
		err = err2;
	return err;
}

int next4_fileattr_get(struct dentry *dentry, struct fileattr *fa)
{
	struct inode *inode = d_inode(dentry);
	struct next4_inode_info *ei = NEXT4_I(inode);
	u32 flags = ei->i_flags & NEXT4_FL_USER_VISIBLE;

	if (S_ISREG(inode->i_mode))
		flags &= ~FS_PROJINHERIT_FL;

	fileattr_fill_flags(fa, flags);
	if (next4_has_feature_project(inode->i_sb))
		fa->fsx_projid = from_kprojid(&init_user_ns, ei->i_projid);

	return 0;
}

int next4_fileattr_set(struct user_namespace *mnt_userns,
		      struct dentry *dentry, struct fileattr *fa)
{
	struct inode *inode = d_inode(dentry);
	u32 flags = fa->flags;
	int err = -EOPNOTSUPP;

	if (flags & ~NEXT4_FL_USER_VISIBLE)
		goto out;

	/*
	 * chattr(1) grabs flags via GETFLAGS, modifies the result and
	 * passes that to SETFLAGS. So we cannot easily make SETFLAGS
	 * more restrictive than just silently masking off visible but
	 * not settable flags as we always did.
	 */
	flags &= NEXT4_FL_USER_MODIFIABLE;
	if (next4_mask_flags(inode->i_mode, flags) != flags)
		goto out;
	err = next4_ioctl_check_immutable(inode, fa->fsx_projid, flags);
	if (err)
		goto out;
	err = next4_ioctl_setflags(inode, flags);
	if (err)
		goto out;
	err = next4_ioctl_setproject(inode, fa->fsx_projid);
out:
	return err;
}

/* So that the fiemap access checks can't overflow on 32 bit machines. */
#define FIEMAP_MAX_EXTENTS	(UINT_MAX / sizeof(struct fiemap_extent))

static int next4_ioctl_get_es_cache(struct file *filp, unsigned long arg)
{
	struct fiemap fiemap;
	struct fiemap __user *ufiemap = (struct fiemap __user *) arg;
	struct fiemap_extent_info fieinfo = { 0, };
	struct inode *inode = file_inode(filp);
	int error;

	if (copy_from_user(&fiemap, ufiemap, sizeof(fiemap)))
		return -EFAULT;

	if (fiemap.fm_extent_count > FIEMAP_MAX_EXTENTS)
		return -EINVAL;

	fieinfo.fi_flags = fiemap.fm_flags;
	fieinfo.fi_extents_max = fiemap.fm_extent_count;
	fieinfo.fi_extents_start = ufiemap->fm_extents;

	error = next4_get_es_cache(inode, &fieinfo, fiemap.fm_start,
			fiemap.fm_length);
	fiemap.fm_flags = fieinfo.fi_flags;
	fiemap.fm_mapped_extents = fieinfo.fi_extents_mapped;
	if (copy_to_user(ufiemap, &fiemap, sizeof(fiemap)))
		error = -EFAULT;

	return error;
}

static int next4_ioctl_checkpoint(struct file *filp, unsigned long arg)
{
	int err = 0;
	__u32 flags = 0;
	unsigned int flush_flags = 0;
	struct super_block *sb = file_inode(filp)->i_sb;

	if (copy_from_user(&flags, (__u32 __user *)arg,
				sizeof(__u32)))
		return -EFAULT;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	/* check for invalid bits set */
	if ((flags & ~NEXT4_IOC_CHECKPOINT_FLAG_VALID) ||
				((flags & NJBD2_JOURNAL_FLUSH_DISCARD) &&
				(flags & NJBD2_JOURNAL_FLUSH_ZEROOUT)))
		return -EINVAL;

	if (!NEXT4_SB(sb)->s_journal)
		return -ENODEV;

	if (flags & ~NEXT4_IOC_CHECKPOINT_FLAG_VALID)
		return -EINVAL;

	if ((flags & NJBD2_JOURNAL_FLUSH_DISCARD) &&
	    !bdev_max_discard_sectors(NEXT4_SB(sb)->s_journal->j_dev))
		return -EOPNOTSUPP;

	if (flags & NEXT4_IOC_CHECKPOINT_FLAG_DRY_RUN)
		return 0;

	if (flags & NEXT4_IOC_CHECKPOINT_FLAG_DISCARD)
		flush_flags |= NJBD2_JOURNAL_FLUSH_DISCARD;

	if (flags & NEXT4_IOC_CHECKPOINT_FLAG_ZEROOUT) {
		flush_flags |= NJBD2_JOURNAL_FLUSH_ZEROOUT;
		pr_info_ratelimited("warning: checkpointing journal with NEXT4_IOC_CHECKPOINT_FLAG_ZEROOUT can be slow");
	}

	njbd2_journal_lock_updates(NEXT4_SB(sb)->s_journal);
	err = njbd2_journal_flush(NEXT4_SB(sb)->s_journal, flush_flags);
	njbd2_journal_unlock_updates(NEXT4_SB(sb)->s_journal);

	return err;
}

static int next4_ioctl_setlabel(struct file *filp, const char __user *user_label)
{
	size_t len;
	int ret = 0;
	char new_label[NEXT4_LABEL_MAX + 1];
	struct super_block *sb = file_inode(filp)->i_sb;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	/*
	 * Copy the maximum length allowed for next4 label with one more to
	 * find the required terminating null byte in order to test the
	 * label length. The on disk label doesn't need to be null terminated.
	 */
	if (copy_from_user(new_label, user_label, NEXT4_LABEL_MAX + 1))
		return -EFAULT;

	len = strnlen(new_label, NEXT4_LABEL_MAX + 1);
	if (len > NEXT4_LABEL_MAX)
		return -EINVAL;

	/*
	 * Clear the buffer after the new label
	 */
	memset(new_label + len, 0, NEXT4_LABEL_MAX - len);

	ret = mnt_want_write_file(filp);
	if (ret)
		return ret;

	ret = next4_update_superblocks_fn(sb, next4_sb_setlabel, new_label);

	mnt_drop_write_file(filp);
	return ret;
}

static int next4_ioctl_getlabel(struct next4_sb_info *sbi, char __user *user_label)
{
	char label[NEXT4_LABEL_MAX + 1];

	/*
	 * NEXT4_LABEL_MAX must always be smaller than FSLABEL_MAX because
	 * FSLABEL_MAX must include terminating null byte, while s_volume_name
	 * does not have to.
	 */
	BUILD_BUG_ON(NEXT4_LABEL_MAX >= FSLABEL_MAX);

	memset(label, 0, sizeof(label));
	lock_buffer(sbi->s_sbh);
	strncpy(label, sbi->s_es->s_volume_name, NEXT4_LABEL_MAX);
	unlock_buffer(sbi->s_sbh);

	if (copy_to_user(user_label, label, sizeof(label)))
		return -EFAULT;
	return 0;
}

static int next4_ioctl_getuuid(struct next4_sb_info *sbi,
			struct fsuuid __user *ufsuuid)
{
	struct fsuuid fsuuid;
	__u8 uuid[UUID_SIZE];

	if (copy_from_user(&fsuuid, ufsuuid, sizeof(fsuuid)))
		return -EFAULT;

	if (fsuuid.fsu_len == 0) {
		fsuuid.fsu_len = UUID_SIZE;
		if (copy_to_user(ufsuuid, &fsuuid, sizeof(fsuuid.fsu_len)))
			return -EFAULT;
		return -EINVAL;
	}

	if (fsuuid.fsu_len != UUID_SIZE || fsuuid.fsu_flags != 0)
		return -EINVAL;

	lock_buffer(sbi->s_sbh);
	memcpy(uuid, sbi->s_es->s_uuid, UUID_SIZE);
	unlock_buffer(sbi->s_sbh);

	if (copy_to_user(&ufsuuid->fsu_uuid[0], uuid, UUID_SIZE))
		return -EFAULT;
	return 0;
}

static int next4_ioctl_setuuid(struct file *filp,
			const struct fsuuid __user *ufsuuid)
{
	int ret = 0;
	struct super_block *sb = file_inode(filp)->i_sb;
	struct fsuuid fsuuid;
	__u8 uuid[UUID_SIZE];

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	/*
	 * If any checksums (group descriptors or metadata) are being used
	 * then the checksum seed feature is required to change the UUID.
	 */
	if (((next4_has_feature_gdt_csum(sb) || next4_has_metadata_csum(sb))
			&& !next4_has_feature_csum_seed(sb))
		|| next4_has_feature_stable_inodes(sb))
		return -EOPNOTSUPP;

	if (copy_from_user(&fsuuid, ufsuuid, sizeof(fsuuid)))
		return -EFAULT;

	if (fsuuid.fsu_len != UUID_SIZE || fsuuid.fsu_flags != 0)
		return -EINVAL;

	if (copy_from_user(uuid, &ufsuuid->fsu_uuid[0], UUID_SIZE))
		return -EFAULT;

	ret = mnt_want_write_file(filp);
	if (ret)
		return ret;

	ret = next4_update_superblocks_fn(sb, next4_sb_setuuid, &uuid);
	mnt_drop_write_file(filp);

	return ret;
}

static long __next4_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct super_block *sb = inode->i_sb;
	struct user_namespace *mnt_userns = file_mnt_user_ns(filp);

	next4_debug("cmd = %u, arg = %lu\n", cmd, arg);

	switch (cmd) {
	case FS_IOC_GETFSMAP:
		return next4_ioc_getfsmap(sb, (void __user *)arg);
	case NEXT4_IOC_GETVERSION:
	case NEXT4_IOC_GETVERSION_OLD:
		return put_user(inode->i_generation, (int __user *) arg);
	case NEXT4_IOC_SETVERSION:
	case NEXT4_IOC_SETVERSION_OLD: {
		handle_t *handle;
		struct next4_iloc iloc;
		__u32 generation;
		int err;

		if (!inode_owner_or_capable(mnt_userns, inode))
			return -EPERM;

		if (next4_has_metadata_csum(inode->i_sb)) {
			next4_warning(sb, "Setting inode version is not "
				     "supported with metadata_csum enabled.");
			return -ENOTTY;
		}

		err = mnt_want_write_file(filp);
		if (err)
			return err;
		if (get_user(generation, (int __user *) arg)) {
			err = -EFAULT;
			goto setversion_out;
		}

		inode_lock(inode);
		handle = next4_journal_start(inode, NEXT4_HT_INODE, 1);
		if (IS_ERR(handle)) {
			err = PTR_ERR(handle);
			goto unlock_out;
		}
		err = next4_reserve_inode_write(handle, inode, &iloc);
		if (err == 0) {
			inode->i_ctime = current_time(inode);
			inode->i_generation = generation;
			err = next4_mark_iloc_dirty(handle, inode, &iloc);
		}
		next4_journal_stop(handle);

unlock_out:
		inode_unlock(inode);
setversion_out:
		mnt_drop_write_file(filp);
		return err;
	}
	case NEXT4_IOC_GROUP_EXTEND: {
		next4_fsblk_t n_blocks_count;
		int err, err2=0;

		err = next4_resize_begin(sb);
		if (err)
			return err;

		if (get_user(n_blocks_count, (__u32 __user *)arg)) {
			err = -EFAULT;
			goto group_extend_out;
		}

		if (next4_has_feature_bigalloc(sb)) {
			next4_msg(sb, KERN_ERR,
				 "Online resizing not supported with bigalloc");
			err = -EOPNOTSUPP;
			goto group_extend_out;
		}

		err = mnt_want_write_file(filp);
		if (err)
			goto group_extend_out;

		err = next4_group_extend(sb, NEXT4_SB(sb)->s_es, n_blocks_count);
		if (NEXT4_SB(sb)->s_journal) {
			njbd2_journal_lock_updates(NEXT4_SB(sb)->s_journal);
			err2 = njbd2_journal_flush(NEXT4_SB(sb)->s_journal, 0);
			njbd2_journal_unlock_updates(NEXT4_SB(sb)->s_journal);
		}
		if (err == 0)
			err = err2;
		mnt_drop_write_file(filp);
group_extend_out:
		err2 = next4_resize_end(sb, false);
		if (err == 0)
			err = err2;
		return err;
	}

	case NEXT4_IOC_MOVE_EXT: {
		struct move_extent me;
		struct fd donor;
		int err;

		if (!(filp->f_mode & FMODE_READ) ||
		    !(filp->f_mode & FMODE_WRITE))
			return -EBADF;

		if (copy_from_user(&me,
			(struct move_extent __user *)arg, sizeof(me)))
			return -EFAULT;
		me.moved_len = 0;

		donor = fdget(me.donor_fd);
		if (!donor.file)
			return -EBADF;

		if (!(donor.file->f_mode & FMODE_WRITE)) {
			err = -EBADF;
			goto mext_out;
		}

		if (next4_has_feature_bigalloc(sb)) {
			next4_msg(sb, KERN_ERR,
				 "Online defrag not supported with bigalloc");
			err = -EOPNOTSUPP;
			goto mext_out;
		} else if (IS_DAX(inode)) {
			next4_msg(sb, KERN_ERR,
				 "Online defrag not supported with DAX");
			err = -EOPNOTSUPP;
			goto mext_out;
		}

		err = mnt_want_write_file(filp);
		if (err)
			goto mext_out;

		err = next4_move_extents(filp, donor.file, me.orig_start,
					me.donor_start, me.len, &me.moved_len);
		mnt_drop_write_file(filp);

		if (copy_to_user((struct move_extent __user *)arg,
				 &me, sizeof(me)))
			err = -EFAULT;
mext_out:
		fdput(donor);
		return err;
	}

	case NEXT4_IOC_GROUP_ADD: {
		struct next4_new_group_data input;

		if (copy_from_user(&input, (struct next4_new_group_input __user *)arg,
				sizeof(input)))
			return -EFAULT;

		return next4_ioctl_group_add(filp, &input);
	}

	case NEXT4_IOC_MIGRATE:
	{
		int err;
		if (!inode_owner_or_capable(mnt_userns, inode))
			return -EACCES;

		err = mnt_want_write_file(filp);
		if (err)
			return err;
		/*
		 * inode_mutex prevent write and truncate on the file.
		 * Read still goes through. We take i_data_sem in
		 * next4_ext_swap_inode_data before we switch the
		 * inode format to prevent read.
		 */
		inode_lock((inode));
		err = next4_ext_migrate(inode);
		inode_unlock((inode));
		mnt_drop_write_file(filp);
		return err;
	}

	case NEXT4_IOC_ALLOC_DA_BLKS:
	{
		int err;
		if (!inode_owner_or_capable(mnt_userns, inode))
			return -EACCES;

		err = mnt_want_write_file(filp);
		if (err)
			return err;
		err = next4_alloc_da_blocks(inode);
		mnt_drop_write_file(filp);
		return err;
	}

	case NEXT4_IOC_SWAP_BOOT:
	{
		int err;
		if (!(filp->f_mode & FMODE_WRITE))
			return -EBADF;
		err = mnt_want_write_file(filp);
		if (err)
			return err;
		err = swap_inode_boot_loader(sb, mnt_userns, inode);
		mnt_drop_write_file(filp);
		return err;
	}

	case NEXT4_IOC_RESIZE_FS: {
		next4_fsblk_t n_blocks_count;
		int err = 0, err2 = 0;
		next4_group_t o_group = NEXT4_SB(sb)->s_groups_count;

		if (copy_from_user(&n_blocks_count, (__u64 __user *)arg,
				   sizeof(__u64))) {
			return -EFAULT;
		}

		err = next4_resize_begin(sb);
		if (err)
			return err;

		err = mnt_want_write_file(filp);
		if (err)
			goto resizefs_out;

		err = next4_resize_fs(sb, n_blocks_count);
		if (NEXT4_SB(sb)->s_journal) {
			next4_fc_mark_ineligible(sb, NEXT4_FC_REASON_RESIZE, NULL);
			njbd2_journal_lock_updates(NEXT4_SB(sb)->s_journal);
			err2 = njbd2_journal_flush(NEXT4_SB(sb)->s_journal, 0);
			njbd2_journal_unlock_updates(NEXT4_SB(sb)->s_journal);
		}
		if (err == 0)
			err = err2;
		mnt_drop_write_file(filp);
		if (!err && (o_group < NEXT4_SB(sb)->s_groups_count) &&
		    next4_has_group_desc_csum(sb) &&
		    test_opt(sb, INIT_INODE_TABLE))
			err = next4_register_li_request(sb, o_group);

resizefs_out:
		err2 = next4_resize_end(sb, true);
		if (err == 0)
			err = err2;
		return err;
	}

	case FITRIM:
	{
		struct fstrim_range range;
		int ret = 0;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;

		if (!bdev_max_discard_sectors(sb->s_bdev))
			return -EOPNOTSUPP;

		/*
		 * We haven't replayed the journal, so we cannot use our
		 * block-bitmap-guided storage zapping commands.
		 */
		if (test_opt(sb, NOLOAD) && next4_has_feature_journal(sb))
			return -EROFS;

		if (copy_from_user(&range, (struct fstrim_range __user *)arg,
		    sizeof(range)))
			return -EFAULT;

		ret = next4_trim_fs(sb, &range);
		if (ret < 0)
			return ret;

		if (copy_to_user((struct fstrim_range __user *)arg, &range,
		    sizeof(range)))
			return -EFAULT;

		return 0;
	}
	case NEXT4_IOC_PRECACHE_EXTENTS:
		return next4_ext_precache(inode);

	case FS_IOC_SET_ENCRYPTION_POLICY:
		if (!next4_has_feature_encrypt(sb))
			return -EOPNOTSUPP;
		return fscrypt_ioctl_set_policy(filp, (const void __user *)arg);

	case FS_IOC_GET_ENCRYPTION_PWSALT:
		return next4_ioctl_get_encryption_pwsalt(filp, (void __user *)arg);

	case FS_IOC_GET_ENCRYPTION_POLICY:
		if (!next4_has_feature_encrypt(sb))
			return -EOPNOTSUPP;
		return fscrypt_ioctl_get_policy(filp, (void __user *)arg);

	case FS_IOC_GET_ENCRYPTION_POLICY_EX:
		if (!next4_has_feature_encrypt(sb))
			return -EOPNOTSUPP;
		return fscrypt_ioctl_get_policy_ex(filp, (void __user *)arg);

	case FS_IOC_ADD_ENCRYPTION_KEY:
		if (!next4_has_feature_encrypt(sb))
			return -EOPNOTSUPP;
		return fscrypt_ioctl_add_key(filp, (void __user *)arg);

	case FS_IOC_REMOVE_ENCRYPTION_KEY:
		if (!next4_has_feature_encrypt(sb))
			return -EOPNOTSUPP;
		return fscrypt_ioctl_remove_key(filp, (void __user *)arg);

	case FS_IOC_REMOVE_ENCRYPTION_KEY_ALL_USERS:
		if (!next4_has_feature_encrypt(sb))
			return -EOPNOTSUPP;
		return fscrypt_ioctl_remove_key_all_users(filp,
							  (void __user *)arg);
	case FS_IOC_GET_ENCRYPTION_KEY_STATUS:
		if (!next4_has_feature_encrypt(sb))
			return -EOPNOTSUPP;
		return fscrypt_ioctl_get_key_status(filp, (void __user *)arg);

	case FS_IOC_GET_ENCRYPTION_NONCE:
		if (!next4_has_feature_encrypt(sb))
			return -EOPNOTSUPP;
		return fscrypt_ioctl_get_nonce(filp, (void __user *)arg);

	case NEXT4_IOC_CLEAR_ES_CACHE:
	{
		if (!inode_owner_or_capable(mnt_userns, inode))
			return -EACCES;
		next4_clear_inode_es(inode);
		return 0;
	}

	case NEXT4_IOC_GETSTATE:
	{
		__u32	state = 0;

		if (next4_test_inode_state(inode, NEXT4_STATE_EXT_PRECACHED))
			state |= NEXT4_STATE_FLAG_EXT_PRECACHED;
		if (next4_test_inode_state(inode, NEXT4_STATE_NEW))
			state |= NEXT4_STATE_FLAG_NEW;
		if (next4_test_inode_state(inode, NEXT4_STATE_NEWENTRY))
			state |= NEXT4_STATE_FLAG_NEWENTRY;
		if (next4_test_inode_state(inode, NEXT4_STATE_DA_ALLOC_CLOSE))
			state |= NEXT4_STATE_FLAG_DA_ALLOC_CLOSE;

		return put_user(state, (__u32 __user *) arg);
	}

	case NEXT4_IOC_GET_ES_CACHE:
		return next4_ioctl_get_es_cache(filp, arg);

	case NEXT4_IOC_SHUTDOWN:
		return next4_shutdown(sb, arg);

	case FS_IOC_ENABLE_VERITY:
		if (!next4_has_feature_verity(sb))
			return -EOPNOTSUPP;
		return fsverity_ioctl_enable(filp, (const void __user *)arg);

	case FS_IOC_MEASURE_VERITY:
		if (!next4_has_feature_verity(sb))
			return -EOPNOTSUPP;
		return fsverity_ioctl_measure(filp, (void __user *)arg);

	case FS_IOC_READ_VERITY_METADATA:
		if (!next4_has_feature_verity(sb))
			return -EOPNOTSUPP;
		return fsverity_ioctl_read_metadata(filp,
						    (const void __user *)arg);

	case NEXT4_IOC_CHECKPOINT:
		return next4_ioctl_checkpoint(filp, arg);

	case FS_IOC_GETFSLABEL:
		return next4_ioctl_getlabel(NEXT4_SB(sb), (void __user *)arg);

	case FS_IOC_SETFSLABEL:
		return next4_ioctl_setlabel(filp,
					   (const void __user *)arg);

	case NEXT4_IOC_GETFSUUID:
		return next4_ioctl_getuuid(NEXT4_SB(sb), (void __user *)arg);
	case NEXT4_IOC_SETFSUUID:
		return next4_ioctl_setuuid(filp, (const void __user *)arg);
	default:
		return -ENOTTY;
	}
}

long next4_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	return __next4_ioctl(filp, cmd, arg);
}

#ifdef CONFIG_COMPAT
long next4_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	/* These are just misnamed, they actually get/put from/to user an int */
	switch (cmd) {
	case NEXT4_IOC32_GETVERSION:
		cmd = NEXT4_IOC_GETVERSION;
		break;
	case NEXT4_IOC32_SETVERSION:
		cmd = NEXT4_IOC_SETVERSION;
		break;
	case NEXT4_IOC32_GROUP_EXTEND:
		cmd = NEXT4_IOC_GROUP_EXTEND;
		break;
	case NEXT4_IOC32_GETVERSION_OLD:
		cmd = NEXT4_IOC_GETVERSION_OLD;
		break;
	case NEXT4_IOC32_SETVERSION_OLD:
		cmd = NEXT4_IOC_SETVERSION_OLD;
		break;
	case NEXT4_IOC32_GETRSVSZ:
		cmd = NEXT4_IOC_GETRSVSZ;
		break;
	case NEXT4_IOC32_SETRSVSZ:
		cmd = NEXT4_IOC_SETRSVSZ;
		break;
	case NEXT4_IOC32_GROUP_ADD: {
		struct compat_next4_new_group_input __user *uinput;
		struct next4_new_group_data input;
		int err;

		uinput = compat_ptr(arg);
		err = get_user(input.group, &uinput->group);
		err |= get_user(input.block_bitmap, &uinput->block_bitmap);
		err |= get_user(input.inode_bitmap, &uinput->inode_bitmap);
		err |= get_user(input.inode_table, &uinput->inode_table);
		err |= get_user(input.blocks_count, &uinput->blocks_count);
		err |= get_user(input.reserved_blocks,
				&uinput->reserved_blocks);
		if (err)
			return -EFAULT;
		return next4_ioctl_group_add(file, &input);
	}
	case NEXT4_IOC_MOVE_EXT:
	case NEXT4_IOC_RESIZE_FS:
	case FITRIM:
	case NEXT4_IOC_PRECACHE_EXTENTS:
	case FS_IOC_SET_ENCRYPTION_POLICY:
	case FS_IOC_GET_ENCRYPTION_PWSALT:
	case FS_IOC_GET_ENCRYPTION_POLICY:
	case FS_IOC_GET_ENCRYPTION_POLICY_EX:
	case FS_IOC_ADD_ENCRYPTION_KEY:
	case FS_IOC_REMOVE_ENCRYPTION_KEY:
	case FS_IOC_REMOVE_ENCRYPTION_KEY_ALL_USERS:
	case FS_IOC_GET_ENCRYPTION_KEY_STATUS:
	case FS_IOC_GET_ENCRYPTION_NONCE:
	case NEXT4_IOC_SHUTDOWN:
	case FS_IOC_GETFSMAP:
	case FS_IOC_ENABLE_VERITY:
	case FS_IOC_MEASURE_VERITY:
	case FS_IOC_READ_VERITY_METADATA:
	case NEXT4_IOC_CLEAR_ES_CACHE:
	case NEXT4_IOC_GETSTATE:
	case NEXT4_IOC_GET_ES_CACHE:
	case NEXT4_IOC_CHECKPOINT:
	case FS_IOC_GETFSLABEL:
	case FS_IOC_SETFSLABEL:
	case NEXT4_IOC_GETFSUUID:
	case NEXT4_IOC_SETFSUUID:
		break;
	default:
		return -ENOIOCTLCMD;
	}
	return next4_ioctl(file, cmd, (unsigned long) compat_ptr(arg));
}
#endif

static void set_overhead(struct next4_super_block *es, const void *arg)
{
	es->s_overhead_clusters = cpu_to_le32(*((unsigned long *) arg));
}

int next4_update_overhead(struct super_block *sb, bool force)
{
	struct next4_sb_info *sbi = NEXT4_SB(sb);

	if (sb_rdonly(sb))
		return 0;
	if (!force &&
	    (sbi->s_overhead == 0 ||
	     sbi->s_overhead == le32_to_cpu(sbi->s_es->s_overhead_clusters)))
		return 0;
	return next4_update_superblocks_fn(sb, set_overhead, &sbi->s_overhead);
}
