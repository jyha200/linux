// SPDX-License-Identifier: GPL-2.0
/*
 * fs/next4/verity.c: fs-verity support for next4
 *
 * Copyright 2019 Google LLC
 */

/*
 * Implementation of fsverity_operations for next4.
 *
 * next4 stores the verity metadata (Merkle tree and fsverity_descriptor) past
 * the end of the file, starting at the first 64K boundary beyond i_size.  This
 * approach works because (a) verity files are readonly, and (b) pages fully
 * beyond i_size aren't visible to userspace but can be read/written internally
 * by next4 with only some relatively small changes to next4.  This approach
 * avoids having to depend on the EA_INODE feature and on rearchitecturing
 * next4's xattr support to support paging multi-gigabyte xattrs into memory, and
 * to support encrypting xattrs.  Note that the verity metadata *must* be
 * encrypted when the file is, since it contains hashes of the plaintext data.
 *
 * Using a 64K boundary rather than a 4K one keeps things ready for
 * architectures with 64K pages, and it doesn't necessarily waste space on-disk
 * since there can be a hole between i_size and the start of the Merkle tree.
 */

#include <linux/quotaops.h>

#include "next4.h"
#include "next4_extents.h"
#include "next4_njbd2.h"

static inline loff_t next4_verity_metadata_pos(const struct inode *inode)
{
	return round_up(inode->i_size, 65536);
}

/*
 * Read some verity metadata from the inode.  __vfs_read() can't be used because
 * we need to read beyond i_size.
 */
static int pagecache_read(struct inode *inode, void *buf, size_t count,
			  loff_t pos)
{
	while (count) {
		size_t n = min_t(size_t, count,
				 PAGE_SIZE - offset_in_page(pos));
		struct page *page;

		page = read_mapping_page(inode->i_mapping, pos >> PAGE_SHIFT,
					 NULL);
		if (IS_ERR(page))
			return PTR_ERR(page);

		memcpy_from_page(buf, page, offset_in_page(pos), n);

		put_page(page);

		buf += n;
		pos += n;
		count -= n;
	}
	return 0;
}

/*
 * Write some verity metadata to the inode for FS_IOC_ENABLE_VERITY.
 * kernel_write() can't be used because the file descriptor is readonly.
 */
static int pagecache_write(struct inode *inode, const void *buf, size_t count,
			   loff_t pos)
{
	struct address_space *mapping = inode->i_mapping;
	const struct address_space_operations *aops = mapping->a_ops;

	if (pos + count > inode->i_sb->s_maxbytes)
		return -EFBIG;

	while (count) {
		size_t n = min_t(size_t, count,
				 PAGE_SIZE - offset_in_page(pos));
		struct page *page;
		void *fsdata;
		int res;

		res = aops->write_begin(NULL, mapping, pos, n, &page, &fsdata);
		if (res)
			return res;

		memcpy_to_page(page, offset_in_page(pos), buf, n);

		res = aops->write_end(NULL, mapping, pos, n, n, page, fsdata);
		if (res < 0)
			return res;
		if (res != n)
			return -EIO;

		buf += n;
		pos += n;
		count -= n;
	}
	return 0;
}

static int next4_begin_enable_verity(struct file *filp)
{
	struct inode *inode = file_inode(filp);
	const int credits = 2; /* superblock and inode for next4_orphan_add() */
	handle_t *handle;
	int err;

	if (IS_DAX(inode) || next4_test_inode_flag(inode, NEXT4_INODE_DAX))
		return -EINVAL;

	if (next4_verity_in_progress(inode))
		return -EBUSY;

	/*
	 * Since the file was opened readonly, we have to initialize the jbd
	 * inode and quotas here and not rely on ->open() doing it.  This must
	 * be done before evicting the inline data.
	 */

	err = next4_inode_attach_jinode(inode);
	if (err)
		return err;

	err = dquot_initialize(inode);
	if (err)
		return err;

	err = next4_convert_inline_data(inode);
	if (err)
		return err;

	if (!next4_test_inode_flag(inode, NEXT4_INODE_EXTENTS)) {
		next4_warning_inode(inode,
				   "verity is only allowed on extent-based files");
		return -EOPNOTSUPP;
	}

	/*
	 * next4 uses the last allocated block to find the verity descriptor, so
	 * we must remove any other blocks past EOF which might confuse things.
	 */
	err = next4_truncate(inode);
	if (err)
		return err;

	handle = next4_journal_start(inode, NEXT4_HT_INODE, credits);
	if (IS_ERR(handle))
		return PTR_ERR(handle);

	err = next4_orphan_add(handle, inode);
	if (err == 0)
		next4_set_inode_state(inode, NEXT4_STATE_VERITY_IN_PROGRESS);

	next4_journal_stop(handle);
	return err;
}

/*
 * next4 stores the verity descriptor beginning on the next filesystem block
 * boundary after the Merkle tree.  Then, the descriptor size is stored in the
 * last 4 bytes of the last allocated filesystem block --- which is either the
 * block in which the descriptor ends, or the next block after that if there
 * weren't at least 4 bytes remaining.
 *
 * We can't simply store the descriptor in an xattr because it *must* be
 * encrypted when next4 encryption is used, but next4 encryption doesn't encrypt
 * xattrs.  Also, if the descriptor includes a large signature blob it may be
 * too large to store in an xattr without the EA_INODE feature.
 */
static int next4_write_verity_descriptor(struct inode *inode, const void *desc,
					size_t desc_size, u64 merkle_tree_size)
{
	const u64 desc_pos = round_up(next4_verity_metadata_pos(inode) +
				      merkle_tree_size, i_blocksize(inode));
	const u64 desc_end = desc_pos + desc_size;
	const __le32 desc_size_disk = cpu_to_le32(desc_size);
	const u64 desc_size_pos = round_up(desc_end + sizeof(desc_size_disk),
					   i_blocksize(inode)) -
				  sizeof(desc_size_disk);
	int err;

	err = pagecache_write(inode, desc, desc_size, desc_pos);
	if (err)
		return err;

	return pagecache_write(inode, &desc_size_disk, sizeof(desc_size_disk),
			       desc_size_pos);
}

static int next4_end_enable_verity(struct file *filp, const void *desc,
				  size_t desc_size, u64 merkle_tree_size)
{
	struct inode *inode = file_inode(filp);
	const int credits = 2; /* superblock and inode for next4_orphan_del() */
	handle_t *handle;
	struct next4_iloc iloc;
	int err = 0;

	/*
	 * If an error already occurred (which fs/verity/ signals by passing
	 * desc == NULL), then only clean-up is needed.
	 */
	if (desc == NULL)
		goto cleanup;

	/* Append the verity descriptor. */
	err = next4_write_verity_descriptor(inode, desc, desc_size,
					   merkle_tree_size);
	if (err)
		goto cleanup;

	/*
	 * Write all pages (both data and verity metadata).  Note that this must
	 * happen before clearing NEXT4_STATE_VERITY_IN_PROGRESS; otherwise pages
	 * beyond i_size won't be written properly.  For crash consistency, this
	 * also must happen before the verity inode flag gets persisted.
	 */
	err = filemap_write_and_wait(inode->i_mapping);
	if (err)
		goto cleanup;

	/*
	 * Finally, set the verity inode flag and remove the inode from the
	 * orphan list (in a single transaction).
	 */

	handle = next4_journal_start(inode, NEXT4_HT_INODE, credits);
	if (IS_ERR(handle)) {
		err = PTR_ERR(handle);
		goto cleanup;
	}

	err = next4_orphan_del(handle, inode);
	if (err)
		goto stop_and_cleanup;

	err = next4_reserve_inode_write(handle, inode, &iloc);
	if (err)
		goto stop_and_cleanup;

	next4_set_inode_flag(inode, NEXT4_INODE_VERITY);
	next4_set_inode_flags(inode, false);
	err = next4_mark_iloc_dirty(handle, inode, &iloc);
	if (err)
		goto stop_and_cleanup;

	next4_journal_stop(handle);

	next4_clear_inode_state(inode, NEXT4_STATE_VERITY_IN_PROGRESS);
	return 0;

stop_and_cleanup:
	next4_journal_stop(handle);
cleanup:
	/*
	 * Verity failed to be enabled, so clean up by truncating any verity
	 * metadata that was written beyond i_size (both from cache and from
	 * disk), removing the inode from the orphan list (if it wasn't done
	 * already), and clearing NEXT4_STATE_VERITY_IN_PROGRESS.
	 */
	truncate_inode_pages(inode->i_mapping, inode->i_size);
	next4_truncate(inode);
	next4_orphan_del(NULL, inode);
	next4_clear_inode_state(inode, NEXT4_STATE_VERITY_IN_PROGRESS);
	return err;
}

static int next4_get_verity_descriptor_location(struct inode *inode,
					       size_t *desc_size_ret,
					       u64 *desc_pos_ret)
{
	struct next4_ext_path *path;
	struct next4_extent *last_extent;
	u32 end_lblk;
	u64 desc_size_pos;
	__le32 desc_size_disk;
	u32 desc_size;
	u64 desc_pos;
	int err;

	/*
	 * Descriptor size is in last 4 bytes of last allocated block.
	 * See next4_write_verity_descriptor().
	 */

	if (!next4_test_inode_flag(inode, NEXT4_INODE_EXTENTS)) {
		NEXT4_ERROR_INODE(inode, "verity file doesn't use extents");
		return -EFSCORRUPTED;
	}

	path = next4_find_extent(inode, EXT_MAX_BLOCKS - 1, NULL, 0);
	if (IS_ERR(path))
		return PTR_ERR(path);

	last_extent = path[path->p_depth].p_ext;
	if (!last_extent) {
		NEXT4_ERROR_INODE(inode, "verity file has no extents");
		next4_ext_drop_refs(path);
		kfree(path);
		return -EFSCORRUPTED;
	}

	end_lblk = le32_to_cpu(last_extent->ee_block) +
		   next4_ext_get_actual_len(last_extent);
	desc_size_pos = (u64)end_lblk << inode->i_blkbits;
	next4_ext_drop_refs(path);
	kfree(path);

	if (desc_size_pos < sizeof(desc_size_disk))
		goto bad;
	desc_size_pos -= sizeof(desc_size_disk);

	err = pagecache_read(inode, &desc_size_disk, sizeof(desc_size_disk),
			     desc_size_pos);
	if (err)
		return err;
	desc_size = le32_to_cpu(desc_size_disk);

	/*
	 * The descriptor is stored just before the desc_size_disk, but starting
	 * on a filesystem block boundary.
	 */

	if (desc_size > INT_MAX || desc_size > desc_size_pos)
		goto bad;

	desc_pos = round_down(desc_size_pos - desc_size, i_blocksize(inode));
	if (desc_pos < next4_verity_metadata_pos(inode))
		goto bad;

	*desc_size_ret = desc_size;
	*desc_pos_ret = desc_pos;
	return 0;

bad:
	NEXT4_ERROR_INODE(inode, "verity file corrupted; can't find descriptor");
	return -EFSCORRUPTED;
}

static int next4_get_verity_descriptor(struct inode *inode, void *buf,
				      size_t buf_size)
{
	size_t desc_size = 0;
	u64 desc_pos = 0;
	int err;

	err = next4_get_verity_descriptor_location(inode, &desc_size, &desc_pos);
	if (err)
		return err;

	if (buf_size) {
		if (desc_size > buf_size)
			return -ERANGE;
		err = pagecache_read(inode, buf, desc_size, desc_pos);
		if (err)
			return err;
	}
	return desc_size;
}

static struct page *next4_read_merkle_tree_page(struct inode *inode,
					       pgoff_t index,
					       unsigned long num_ra_pages)
{
	DEFINE_READAHEAD(ractl, NULL, NULL, inode->i_mapping, index);
	struct page *page;

	index += next4_verity_metadata_pos(inode) >> PAGE_SHIFT;

	page = find_get_page_flags(inode->i_mapping, index, FGP_ACCESSED);
	if (!page || !PageUptodate(page)) {
		if (page)
			put_page(page);
		else if (num_ra_pages > 1)
			page_cache_ra_unbounded(&ractl, num_ra_pages, 0);
		page = read_mapping_page(inode->i_mapping, index, NULL);
	}
	return page;
}

static int next4_write_merkle_tree_block(struct inode *inode, const void *buf,
					u64 index, int log_blocksize)
{
	loff_t pos = next4_verity_metadata_pos(inode) + (index << log_blocksize);

	return pagecache_write(inode, buf, 1 << log_blocksize, pos);
}

const struct fsverity_operations next4_verityops = {
	.begin_enable_verity	= next4_begin_enable_verity,
	.end_enable_verity	= next4_end_enable_verity,
	.get_verity_descriptor	= next4_get_verity_descriptor,
	.read_merkle_tree_page	= next4_read_merkle_tree_page,
	.write_merkle_tree_block = next4_write_merkle_tree_block,
};
