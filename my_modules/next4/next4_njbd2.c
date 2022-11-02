// SPDX-License-Identifier: GPL-2.0
/*
 * Interface between next4 and JBD
 */

#include "next4_njbd2.h"

#include <trace/events/next4.h>

int next4_inode_journal_mode(struct inode *inode)
{
	if (NEXT4_JOURNAL(inode) == NULL)
		return NEXT4_INODE_WRITEBACK_DATA_MODE;	/* writeback */
	/* We do not support data journalling with delayed allocation */
	if (!S_ISREG(inode->i_mode) ||
	    next4_test_inode_flag(inode, NEXT4_INODE_EA_INODE) ||
	    test_opt(inode->i_sb, DATA_FLAGS) == NEXT4_MOUNT_JOURNAL_DATA ||
	    (next4_test_inode_flag(inode, NEXT4_INODE_JOURNAL_DATA) &&
	    !test_opt(inode->i_sb, DELALLOC))) {
		/* We do not support data journalling for encrypted data */
		if (S_ISREG(inode->i_mode) && IS_ENCRYPTED(inode))
			return NEXT4_INODE_ORDERED_DATA_MODE;  /* ordered */
		return NEXT4_INODE_JOURNAL_DATA_MODE;	/* journal data */
	}
	if (test_opt(inode->i_sb, DATA_FLAGS) == NEXT4_MOUNT_ORDERED_DATA)
		return NEXT4_INODE_ORDERED_DATA_MODE;	/* ordered */
	if (test_opt(inode->i_sb, DATA_FLAGS) == NEXT4_MOUNT_WRITEBACK_DATA)
		return NEXT4_INODE_WRITEBACK_DATA_MODE;	/* writeback */
	BUG();
}

/* Just increment the non-pointer handle value */
static handle_t *next4_get_nojournal(void)
{
	handle_t *handle = current->journal_info;
	unsigned long ref_cnt = (unsigned long)handle;

	BUG_ON(ref_cnt >= NEXT4_NOJOURNAL_MAX_REF_COUNT);

	ref_cnt++;
	handle = (handle_t *)ref_cnt;

	current->journal_info = handle;
	return handle;
}


/* Decrement the non-pointer handle value */
static void next4_put_nojournal(handle_t *handle)
{
	unsigned long ref_cnt = (unsigned long)handle;

	BUG_ON(ref_cnt == 0);

	ref_cnt--;
	handle = (handle_t *)ref_cnt;

	current->journal_info = handle;
}

/*
 * Wrappers for njbd2_journal_start/end.
 */
static int next4_journal_check_start(struct super_block *sb)
{
	journal_t *journal;

	might_sleep();

	if (unlikely(next4_forced_shutdown(NEXT4_SB(sb))))
		return -EIO;

	if (sb_rdonly(sb))
		return -EROFS;
	WARN_ON(sb->s_writers.frozen == SB_FREEZE_COMPLETE);
	journal = NEXT4_SB(sb)->s_journal;
	/*
	 * Special case here: if the journal has aborted behind our
	 * backs (eg. EIO in the commit thread), then we still need to
	 * take the FS itself readonly cleanly.
	 */
	if (journal && is_journal_aborted(journal)) {
		next4_abort(sb, -journal->j_errno, "Detected aborted journal");
		return -EROFS;
	}
	return 0;
}

handle_t *__next4_journal_start_sb(struct super_block *sb, unsigned int line,
				  int type, int blocks, int rsv_blocks,
				  int revoke_creds)
{
	journal_t *journal;
	int err;

	trace_next4_journal_start(sb, blocks, rsv_blocks, revoke_creds,
				 _RET_IP_);
	err = next4_journal_check_start(sb);
	if (err < 0)
		return ERR_PTR(err);

	journal = NEXT4_SB(sb)->s_journal;
	if (!journal || (NEXT4_SB(sb)->s_mount_state & NEXT4_FC_REPLAY))
		return next4_get_nojournal();
	return njbd2__journal_start(journal, blocks, rsv_blocks, revoke_creds,
				   GFP_NOFS, type, line);
}

int __next4_journal_stop(const char *where, unsigned int line, handle_t *handle)
{
	struct super_block *sb;
	int err;
	int rc;

	if (!next4_handle_valid(handle)) {
		next4_put_nojournal(handle);
		return 0;
	}

	err = handle->h_err;
	if (!handle->h_transaction) {
		rc = njbd2_journal_stop(handle);
		return err ? err : rc;
	}

	sb = handle->h_transaction->t_journal->j_private;
	rc = njbd2_journal_stop(handle);

	if (!err)
		err = rc;
	if (err)
		__next4_std_error(sb, where, line, err);
	return err;
}

handle_t *__next4_journal_start_reserved(handle_t *handle, unsigned int line,
					int type)
{
	struct super_block *sb;
	int err;

	if (!next4_handle_valid(handle))
		return next4_get_nojournal();

	sb = handle->h_journal->j_private;
	trace_next4_journal_start_reserved(sb,
				njbd2_handle_buffer_credits(handle), _RET_IP_);
	err = next4_journal_check_start(sb);
	if (err < 0) {
		njbd2_journal_free_reserved(handle);
		return ERR_PTR(err);
	}

	err = njbd2_journal_start_reserved(handle, type, line);
	if (err < 0)
		return ERR_PTR(err);
	return handle;
}

int __next4_journal_ensure_credits(handle_t *handle, int check_cred,
				  int extend_cred, int revoke_cred)
{
	if (!next4_handle_valid(handle))
		return 0;
	if (is_handle_aborted(handle))
		return -EROFS;
	if (njbd2_handle_buffer_credits(handle) >= check_cred &&
	    handle->h_revoke_credits >= revoke_cred)
		return 0;
	extend_cred = max(0, extend_cred - njbd2_handle_buffer_credits(handle));
	revoke_cred = max(0, revoke_cred - handle->h_revoke_credits);
	return next4_journal_extend(handle, extend_cred, revoke_cred);
}

static void next4_journal_abort_handle(const char *caller, unsigned int line,
				      const char *err_fn,
				      struct buffer_head *bh,
				      handle_t *handle, int err)
{
	char nbuf[16];
	const char *errstr = next4_decode_error(NULL, err, nbuf);

	BUG_ON(!next4_handle_valid(handle));

	if (bh)
		BUFFER_TRACE(bh, "abort");

	if (!handle->h_err)
		handle->h_err = err;

	if (is_handle_aborted(handle))
		return;

	printk(KERN_ERR "NEXT4-fs: %s:%d: aborting transaction: %s in %s\n",
	       caller, line, errstr, err_fn);

	njbd2_journal_abort_handle(handle);
}

static void next4_check_bdev_write_error(struct super_block *sb)
{
	struct address_space *mapping = sb->s_bdev->bd_inode->i_mapping;
	struct next4_sb_info *sbi = NEXT4_SB(sb);
	int err;

	/*
	 * If the block device has write error flag, it may have failed to
	 * async write out metadata buffers in the background. In this case,
	 * we could read old data from disk and write it out again, which
	 * may lead to on-disk filesystem inconsistency.
	 */
	if (errseq_check(&mapping->wb_err, READ_ONCE(sbi->s_bdev_wb_err))) {
		spin_lock(&sbi->s_bdev_wb_lock);
		err = errseq_check_and_advance(&mapping->wb_err, &sbi->s_bdev_wb_err);
		spin_unlock(&sbi->s_bdev_wb_lock);
		if (err)
			next4_error_err(sb, -err,
				       "Error while async write back metadata");
	}
}

int __next4_journal_get_write_access(const char *where, unsigned int line,
				    handle_t *handle, struct super_block *sb,
				    struct buffer_head *bh,
				    enum next4_journal_trigger_type trigger_type)
{
	int err;

	might_sleep();

	if (bh->b_bdev->bd_super)
		next4_check_bdev_write_error(bh->b_bdev->bd_super);

	if (next4_handle_valid(handle)) {
		err = njbd2_journal_get_write_access(handle, bh);
		if (err) {
			next4_journal_abort_handle(where, line, __func__, bh,
						  handle, err);
			return err;
		}
	}
	if (trigger_type == NEXT4_JTR_NONE || !next4_has_metadata_csum(sb))
		return 0;
	BUG_ON(trigger_type >= NEXT4_JOURNAL_TRIGGER_COUNT);
	njbd2_journal_set_triggers(bh,
		&NEXT4_SB(sb)->s_journal_triggers[trigger_type].tr_triggers);
	return 0;
}

/*
 * The next4 forget function must perform a revoke if we are freeing data
 * which has been journaled.  Metadata (eg. indirect blocks) must be
 * revoked in all cases.
 *
 * "bh" may be NULL: a metadata block may have been freed from memory
 * but there may still be a record of it in the journal, and that record
 * still needs to be revoked.
 */
int __next4_forget(const char *where, unsigned int line, handle_t *handle,
		  int is_metadata, struct inode *inode,
		  struct buffer_head *bh, next4_fsblk_t blocknr)
{
	int err;

	might_sleep();

	trace_next4_forget(inode, is_metadata, blocknr);
	BUFFER_TRACE(bh, "enter");

	next4_debug("forgetting bh %p: is_metadata=%d, mode %o, data mode %x\n",
		  bh, is_metadata, inode->i_mode,
		  test_opt(inode->i_sb, DATA_FLAGS));

	/* In the no journal case, we can just do a bforget and return */
	if (!next4_handle_valid(handle)) {
		bforget(bh);
		return 0;
	}

	/* Never use the revoke function if we are doing full data
	 * journaling: there is no need to, and a V1 superblock won't
	 * support it.  Otherwise, only skip the revoke on un-journaled
	 * data blocks. */

	if (test_opt(inode->i_sb, DATA_FLAGS) == NEXT4_MOUNT_JOURNAL_DATA ||
	    (!is_metadata && !next4_should_journal_data(inode))) {
		if (bh) {
			BUFFER_TRACE(bh, "call njbd2_journal_forget");
			err = njbd2_journal_forget(handle, bh);
			if (err)
				next4_journal_abort_handle(where, line, __func__,
							  bh, handle, err);
			return err;
		}
		return 0;
	}

	/*
	 * data!=journal && (is_metadata || should_journal_data(inode))
	 */
	BUFFER_TRACE(bh, "call njbd2_journal_revoke");
	err = njbd2_journal_revoke(handle, blocknr, bh);
	if (err) {
		next4_journal_abort_handle(where, line, __func__,
					  bh, handle, err);
		__next4_error(inode->i_sb, where, line, true, -err, 0,
			     "error %d when attempting revoke", err);
	}
	BUFFER_TRACE(bh, "exit");
	return err;
}

int __next4_journal_get_create_access(const char *where, unsigned int line,
				handle_t *handle, struct super_block *sb,
				struct buffer_head *bh,
				enum next4_journal_trigger_type trigger_type)
{
	int err;

	if (!next4_handle_valid(handle))
		return 0;

	err = njbd2_journal_get_create_access(handle, bh);
	if (err) {
		next4_journal_abort_handle(where, line, __func__, bh, handle,
					  err);
		return err;
	}
	if (trigger_type == NEXT4_JTR_NONE || !next4_has_metadata_csum(sb))
		return 0;
	BUG_ON(trigger_type >= NEXT4_JOURNAL_TRIGGER_COUNT);
	njbd2_journal_set_triggers(bh,
		&NEXT4_SB(sb)->s_journal_triggers[trigger_type].tr_triggers);
	return 0;
}

int __next4_handle_dirty_metadata(const char *where, unsigned int line,
				 handle_t *handle, struct inode *inode,
				 struct buffer_head *bh)
{
	int err = 0;

	might_sleep();

	set_buffer_meta(bh);
	set_buffer_prio(bh);
	set_buffer_uptodate(bh);
	if (next4_handle_valid(handle)) {
		err = njbd2_journal_dirty_metadata(handle, bh);
		/* Errors can only happen due to aborted journal or a nasty bug */
		if (!is_handle_aborted(handle) && WARN_ON_ONCE(err)) {
			next4_journal_abort_handle(where, line, __func__, bh,
						  handle, err);
			if (inode == NULL) {
				pr_err("NEXT4: njbd2_journal_dirty_metadata "
				       "failed: handle type %u started at "
				       "line %u, credits %u/%u, errcode %d",
				       handle->h_type,
				       handle->h_line_no,
				       handle->h_requested_credits,
				       njbd2_handle_buffer_credits(handle), err);
				return err;
			}
			next4_error_inode(inode, where, line,
					 bh->b_blocknr,
					 "journal_dirty_metadata failed: "
					 "handle type %u started at line %u, "
					 "credits %u/%u, errcode %d",
					 handle->h_type,
					 handle->h_line_no,
					 handle->h_requested_credits,
					 njbd2_handle_buffer_credits(handle),
					 err);
		}
	} else {
		if (inode)
			mark_buffer_dirty_inode(bh, inode);
		else
			mark_buffer_dirty(bh);
		if (inode && inode_needs_sync(inode)) {
			sync_dirty_buffer(bh);
			if (buffer_req(bh) && !buffer_uptodate(bh)) {
				next4_error_inode_err(inode, where, line,
						     bh->b_blocknr, EIO,
					"IO error syncing itable block");
				err = -EIO;
			}
		}
	}
	return err;
}
