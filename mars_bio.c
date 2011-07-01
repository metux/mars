// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

// Bio brick (interface to blkdev IO via kernel bios)

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING
//#define IO_DEBUGGING

//#define FAKE_IO

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/bio.h>
#include <linux/kthread.h>

#include "mars.h"

///////////////////////// own type definitions ////////////////////////

#include "mars_bio.h"

static void bio_ref_put(struct bio_output *output, struct mref_object *mref);

///////////////////////// own helper functions ////////////////////////

/* This is called from the kernel bio layer.
 */
static
void bio_callback(struct bio *bio, int code)
{
	struct bio_mref_aspect *mref_a = bio->bi_private;
	struct bio_brick *brick;
	unsigned long flags;

	CHECK_PTR(mref_a, err);
	CHECK_PTR(mref_a->output, err);
	brick = mref_a->output->brick;
	CHECK_PTR(brick, err);

	mref_a->status_code = code;

	spin_lock_irqsave(&brick->lock, flags);
	if (list_empty(&mref_a->io_head)) {
		list_add_tail(&mref_a->io_head, &brick->completed_list);
		atomic_inc(&brick->completed_count);
	}
	spin_unlock_irqrestore(&brick->lock, flags);

	wake_up_interruptible(&brick->event);
	return;

err:
	MARS_FAT("cannot handle bio callback\n");
}

/* Map from kernel address/length to struct page (if not already known),
 * check alignment constraints, create bio from it.
 * Return the length (may be smaller than requested).
 */
static
int make_bio(struct bio_brick *brick, void *data, int len, loff_t pos, struct bio_mref_aspect *private, struct bio **_bio)
{
	unsigned long long sector;
	int sector_offset;
	int data_offset;
	int page_offset;
	int page_len;
	int bvec_count;
	int rest_len = len;
	int result_len = 0;
	int status;
	int i;
	struct bio *bio = NULL;
	struct block_device *bdev;

	status = -EINVAL;
	CHECK_PTR(brick, out);
	bdev = brick->bdev;
	CHECK_PTR(bdev, out);

	if (unlikely(rest_len <= 0)) {
		MARS_ERR("bad bio len %d\n", rest_len);
		goto out;
	}

	sector = pos >> 9;                     // TODO: make dynamic
	sector_offset = pos & ((1 << 9) - 1);  // TODO: make dynamic
	data_offset = ((unsigned long)data) & ((1 << 9) - 1);  // TODO: make dynamic

	if (unlikely(sector_offset > 0)) {
		MARS_ERR("odd sector offset %d\n", sector_offset);
		goto out;
	}
	if (unlikely(sector_offset != data_offset)) {
		MARS_ERR("bad alignment: sector_offset %d != data_offet %d\n", sector_offset, data_offset);
		goto out;
	}
	if (unlikely(rest_len & ((1 << 9) - 1))) {
		MARS_ERR("odd length %d\n", rest_len);
		goto out;
	}

	page_offset = ((unsigned long)data) & (PAGE_SIZE-1);
	page_len = rest_len + page_offset;
	bvec_count = (page_len - 1) / PAGE_SIZE + 1;
	if (bvec_count > brick->bvec_max) {
		bvec_count = brick->bvec_max;
	}

	MARS_IO("sector_offset = %d data = %p pos = %lld rest_len = %d page_offset = %d page_len = %d bvec_count = %d\n", sector_offset, data, pos, rest_len, page_offset, page_len, bvec_count);

	bio = bio_alloc(GFP_MARS, bvec_count);
	status = -ENOMEM;
	if (unlikely(!bio)) {
		goto out;
	}

	for (i = 0; i < bvec_count && rest_len > 0; i++) {
		struct page *page;
		int this_rest = PAGE_SIZE - page_offset;
		int this_len = rest_len;

		if (this_len > this_rest) {
			this_len = this_rest;
		}
#ifdef MARS_DEBUGGING
		if (unlikely(!virt_addr_valid(data))) {
			MARS_ERR("invalid virtual kernel address %p\n", data);
			status = -EINVAL;
			goto out;
		}
#endif

		page = mars_iomap(data, &page_offset, &this_len);
		if (unlikely(!page)) {
			MARS_ERR("cannot iomap() kernel address %p\n", data);
			status = -EINVAL;
			goto out;
		}

		MARS_IO("  i = %d page = %p bv_len = %d bv_offset = %d\n", i, page, this_len, page_offset);

		bio->bi_io_vec[i].bv_page = page;
		bio->bi_io_vec[i].bv_len = this_len;
		bio->bi_io_vec[i].bv_offset = page_offset;

		data += this_len;
		rest_len -= this_len;
		result_len += this_len;
		page_offset = 0;
		//MARS_IO("page_offset=%d this_len=%d (new len=%d, new status=%d)\n", page_offset, this_len, rest_len, status);
	}

	if (unlikely(rest_len != 0)) {
		MARS_ERR("computation of bvec_count %d was wrong, diff=%d\n", bvec_count, rest_len);
		status = -EIO;
		goto out;
	}

	bio->bi_vcnt = i;
	bio->bi_idx = 0;
	bio->bi_size = result_len;
	bio->bi_sector = sector;
	bio->bi_bdev = bdev;
	bio->bi_private = private;
	bio->bi_end_io = bio_callback;
	bio->bi_rw = 0; // must be filled in later
	status = result_len;

out:
	if (unlikely(status < 0)) {
		MARS_ERR("error %d\n", status);
		if (bio) {
			bio_put(bio);
			bio = NULL;
		}
	}
	*_bio = bio;
	return status;
}


////////////////// own brick / input / output operations //////////////////

static int bio_get_info(struct bio_output *output, struct mars_info *info)
{
	struct bio_brick *brick = output->brick;
	int status = 0;
	info->current_size = brick->total_size;
	MARS_DBG("determined device size = %lld\n", info->current_size);
	info->backing_file = brick->filp;
	if (!brick->filp) {
		status = -ENOENT;
	}
	return status;
}

static int bio_ref_get(struct bio_output *output, struct mref_object *mref)
{
	struct bio_mref_aspect *mref_a = bio_mref_get_aspect(output, mref);
	int status = -EINVAL;

	CHECK_PTR(mref_a, done);
	CHECK_PTR(output->brick, done);
	_CHECK_ATOMIC(&mref->ref_count, !=,  0);

	if (mref_a->output)
		goto ok;
	mref_a->output = output;
	mref_a->bio = NULL;

	if (!mref->ref_data) { // buffered IO.
		status = -ENOMEM;
		mref->ref_data = mars_alloc(mref->ref_pos, (mref_a->alloc_len = mref->ref_len));
		if (unlikely(!mref->ref_data)) {
			goto done;
		}
		mref_a->do_dealloc = true;
	}

	status = make_bio(output->brick, mref->ref_data, mref->ref_len, mref->ref_pos, mref_a, &mref_a->bio);
	if (unlikely(status < 0 || !mref_a->bio)) {
		MARS_ERR("could not create bio, status = %d\n", status);
		goto done;
	}

	MARS_IO("len %d -> %d fly = %d\n", mref->ref_len, status, atomic_read(&output->brick->fly_count));

	mref->ref_len = status;
ok:
	atomic_inc(&mref->ref_count);
	status = 0;

done:
	return status;
}

static
void bio_ref_put(struct bio_output *output, struct mref_object *mref)
{
	struct bio_mref_aspect *mref_a;

	CHECK_ATOMIC(&mref->ref_count, 1);
	if (!atomic_dec_and_test(&mref->ref_count)) {
		goto done;
	}

	MARS_IO("deallocating\n");

	mref->ref_total_size = output->brick->total_size;

	mref_a = bio_mref_get_aspect(output, mref);
	CHECK_PTR(mref_a, err);

	if (likely(mref_a->bio)) {
#ifdef MARS_DEBUGGING
		int bi_cnt = atomic_read(&mref_a->bio->bi_cnt);
		if (bi_cnt > 1) {
			MARS_DBG("bi_cnt = %d\n", bi_cnt);
		}
#endif
		bio_put(mref_a->bio);
		mref_a->bio = NULL;
	}
	if (mref_a->do_dealloc) {
		MARS_IO("free page\n");
		mars_free(mref->ref_data, mref_a->alloc_len);
		mref->ref_data = NULL;
	}
	bio_free_mref(mref);

done:
	return;

err:
	MARS_FAT("cannot work\n");
}

static
void _bio_ref_io(struct bio_output *output, struct mref_object *mref)
{
	struct bio_brick *brick = output->brick;
	struct bio_mref_aspect *mref_a = bio_mref_get_aspect(output, mref);
	struct bio *bio;
	struct generic_callback *cb;
	int rw;
	int status = -EINVAL;

	CHECK_PTR(mref_a, err);
	bio = mref_a->bio;
	CHECK_PTR(bio, err);

	CHECK_ATOMIC(&mref->ref_count, 1);
	atomic_inc(&mref->ref_count);
	atomic_inc(&brick->fly_count);

	bio_get(bio);

	rw = mref->ref_rw & 1;
	if (brick->do_noidle) {
		rw |= (1 << BIO_RW_NOIDLE);
	}
	if (!mref->ref_skip_sync) {
		if (brick->do_sync) {
			rw |= (1 << BIO_RW_SYNCIO);
		}
		if (brick->do_unplug) {
			rw |= (1 << BIO_RW_UNPLUG);
		}
	}

	MARS_IO("starting IO rw = %d fly = %d\n", rw, atomic_read(&brick->fly_count));
	mars_trace(mref, "bio_submit");

#ifdef FAKE_IO
	bio->bi_end_io(bio, 0);
#else
	bio->bi_rw = rw;
	submit_bio(rw, bio);
#endif

	status = 0;
	if (unlikely(bio_flagged(bio, BIO_EOPNOTSUPP)))
		status = -EOPNOTSUPP;

	MARS_IO("submitted\n");

	if (likely(status >= 0))
		goto done;

	bio_put(bio);
	atomic_dec(&brick->fly_count);

err:
	MARS_ERR("IO error %d\n", status);
	cb = mref->ref_cb;
	if (cb) {
		cb->cb_error = status;
		cb->cb_fn(cb);
	}
done: ;
}

static
void bio_ref_io(struct bio_output *output, struct mref_object *mref)
{
	if (mref->ref_prio == MARS_PRIO_LOW) { // queue for background IO
		struct bio_mref_aspect *mref_a = bio_mref_get_aspect(output, mref);
		struct bio_brick *brick = output->brick;
		unsigned long flags;
		
		spin_lock_irqsave(&brick->lock, flags);
		list_add_tail(&mref_a->io_head, &brick->background_list);
		spin_unlock_irqrestore(&brick->lock, flags);
		atomic_inc(&brick->background_count);
		atomic_inc(&brick->total_background_count);
		wake_up_interruptible(&brick->event);
		return;
	}
	// foreground IO: start immediately
	_bio_ref_io(output, mref);
}

static int bio_thread(void *data)
{
	struct bio_brick *brick = data;

	MARS_INF("bio kthread has started on '%s'.\n", brick->brick_name);

	for (;;) {
		LIST_HEAD(tmp_list);
		unsigned long flags;

		wait_event_interruptible_timeout(
			brick->event,
			atomic_read(&brick->completed_count) > 0 ||
			(atomic_read(&brick->background_count) > 0 && !atomic_read(&brick->fly_count)),
			12 * HZ);

		spin_lock_irqsave(&brick->lock, flags);
		list_replace_init(&brick->completed_list, &tmp_list);
		spin_unlock_irqrestore(&brick->lock, flags);

		for (;;) {
			struct list_head *tmp;
			struct bio_mref_aspect *mref_a;
			struct mref_object *mref;
			struct generic_callback *cb;
			int code;

			if (list_empty(&tmp_list)) {
				if (kthread_should_stop())
					goto done;
				break;
			}
			
			tmp = tmp_list.next;
			list_del_init(tmp);
			atomic_dec(&brick->completed_count);
			mref_a = container_of(tmp, struct bio_mref_aspect, io_head);
			
			code = mref_a->status_code;
			MARS_IO("completed , status = %d\n", code);
		
			mref = mref_a->object;

			mars_trace(mref, "bio_endio");

			cb = mref->ref_cb;
			cb->cb_error = code;
			if (code < 0) {
				MARS_ERR("IO error %d\n", code);
			} else {
				mref->ref_flags |= MREF_UPTODATE;
			}
			
			cb->cb_fn(cb);
			
			atomic_dec(&brick->fly_count);
			atomic_inc(&brick->total_completed_count);
			MARS_IO("fly = %d\n", atomic_read(&brick->fly_count));
			if (likely(mref_a->bio)) {
				bio_put(mref_a->bio);
			}
			bio_ref_put(mref_a->output, mref);
		}

		if (!atomic_read(&brick->fly_count) && atomic_read(&brick->background_count) > 0) {
			struct list_head *tmp;
			struct bio_mref_aspect *mref_a;
			struct mref_object *mref;

			atomic_dec(&brick->background_count);
			spin_lock_irqsave(&brick->lock, flags);
			tmp = brick->background_list.next;
			list_del_init(tmp);
			spin_unlock_irqrestore(&brick->lock, flags);

			mref_a = container_of(tmp, struct bio_mref_aspect, io_head);
			mref = mref_a->object;
			if (unlikely(!mref)) {
				MARS_ERR("invalid mref\n");
				continue;
			}

			_bio_ref_io(mref_a->output, mref);
		}
	}
done:
	MARS_INF("bio kthread has stopped.\n");
	return 0;
}

static int bio_switch(struct bio_brick *brick)
{
	int status = 0;
	if (brick->power.button) {
		mars_power_led_off((void*)brick, false);
		
		if (!brick->bdev) {
			static int index = 0;
			const char *path = brick->brick_name;
			int flags = O_RDWR | O_LARGEFILE;
			int prot = 0600;
			struct inode *inode;
			struct request_queue *q;
			mm_segment_t oldfs;

			oldfs = get_fs();
			set_fs(get_ds());
			brick->filp = filp_open(path, flags, prot);
			set_fs(oldfs);

			if (!brick->filp) {
				MARS_ERR("cannot open '%s'\n", path);
				status = -ENOENT;
				goto done;
			}
			
			status = -EINVAL;
			CHECK_PTR(brick->filp->f_mapping, done);
			inode = brick->filp->f_mapping->host;
			CHECK_PTR(inode, done);
			if (!S_ISBLK(inode->i_mode)) {
				MARS_ERR("sorry, '%s' is not a block device\n", path);
				goto done;
			}

			q = bdev_get_queue(inode->i_bdev);
			CHECK_PTR(q, done);

			MARS_INF("ra_pages OLD=%lu NEW=%d\n", q->backing_dev_info.ra_pages, brick->ra_pages);
			q->backing_dev_info.ra_pages = brick->ra_pages;
			brick->bvec_max = queue_max_hw_sectors(q) >> (PAGE_SHIFT - 9);
			brick->total_size = inode->i_size;
			brick->thread = kthread_create(bio_thread, brick, "mars_bio%d", index++);
			if (IS_ERR(brick->thread)) {
				status = PTR_ERR(brick->thread);
				MARS_ERR("cannot create thread\n");
				brick->thread = NULL;
			}
			if (brick->thread) {
				brick->bdev = inode->i_bdev;
				wake_up_process(brick->thread);
				status = 0;
			}
		}
		if (brick->bdev) {
			mars_power_led_on((void*)brick, true);
		}
	} else {
		mars_power_led_on((void*)brick, false);

		// TODO: wait for IO completion

		if (brick->filp) {
			filp_close(brick->filp, NULL);
			brick->filp = NULL;
		}
		if (brick->thread) {
			kthread_stop(brick->thread);
			brick->thread = NULL;
		}
		brick->bdev = NULL;
		brick->total_size = 0;

		mars_power_led_off((void*)brick, true);
	}

done:
	if (status < 0 && brick->filp) {
		filp_close(brick->filp, NULL);
		brick->filp = NULL;
	}
	return status;
}


//////////////// informational / statistics ///////////////

static noinline
char *bio_statistics(struct bio_brick *brick, int verbose)
{
	char *res = kmalloc(512, GFP_MARS);
	if (!res)
		return NULL;

	// FIXME: check for allocation overflows

	sprintf(res, "total completed = %d background = %d | flying = %d completing = %d background = %d\n", atomic_read(&brick->total_completed_count), atomic_read(&brick->total_background_count), atomic_read(&brick->fly_count), atomic_read(&brick->completed_count), atomic_read(&brick->background_count));

	return res;
}

static noinline
void bio_reset_statistics(struct bio_brick *brick)
{
	atomic_set(&brick->total_completed_count, 0);
	atomic_set(&brick->total_background_count, 0);
}


//////////////// object / aspect constructors / destructors ///////////////

static int bio_mref_aspect_init_fn(struct generic_aspect *_ini, void *_init_data)
{
	struct bio_mref_aspect *ini = (void*)_ini;
	INIT_LIST_HEAD(&ini->io_head);
	return 0;
}

static void bio_mref_aspect_exit_fn(struct generic_aspect *_ini, void *_init_data)
{
	struct bio_mref_aspect *ini = (void*)_ini;
	(void)ini;
}

MARS_MAKE_STATICS(bio);

////////////////////// brick constructors / destructors ////////////////////

static int bio_brick_construct(struct bio_brick *brick)
{
	spin_lock_init(&brick->lock);
	INIT_LIST_HEAD(&brick->background_list);
	INIT_LIST_HEAD(&brick->completed_list);
	init_waitqueue_head(&brick->event);
	return 0;
}

static int bio_brick_destruct(struct bio_brick *brick)
{
	return 0;
}

static int bio_output_construct(struct bio_output *output)
{
	return 0;
}

static int bio_output_destruct(struct bio_output *output)
{
	return 0;
}

///////////////////////// static structs ////////////////////////

static struct bio_brick_ops bio_brick_ops = {
	.brick_switch = bio_switch,
	.brick_statistics = bio_statistics,
	.reset_statistics = bio_reset_statistics,
};

static struct bio_output_ops bio_output_ops = {
	.make_object_layout = bio_make_object_layout,
	.mars_get_info = bio_get_info,
	.mref_get = bio_ref_get,
	.mref_put = bio_ref_put,
	.mref_io = bio_ref_io,
};

const struct bio_input_type bio_input_type = {
	.type_name = "bio_input",
	.input_size = sizeof(struct bio_input),
};

static const struct bio_input_type *bio_input_types[] = {
	&bio_input_type,
};

const struct bio_output_type bio_output_type = {
	.type_name = "bio_output",
	.output_size = sizeof(struct bio_output),
	.master_ops = &bio_output_ops,
	.output_construct = &bio_output_construct,
	.output_destruct = &bio_output_destruct,
	.aspect_types = bio_aspect_types,
	.layout_code = {
		[BRICK_OBJ_MREF] = LAYOUT_ALL,
	}
};

static const struct bio_output_type *bio_output_types[] = {
	&bio_output_type,
};

const struct bio_brick_type bio_brick_type = {
	.type_name = "bio_brick",
	.brick_size = sizeof(struct bio_brick),
	.max_inputs = 0,
	.max_outputs = 1,
	.master_ops = &bio_brick_ops,
	.default_input_types = bio_input_types,
	.default_output_types = bio_output_types,
	.brick_construct = &bio_brick_construct,
	.brick_destruct = &bio_brick_destruct,
};
EXPORT_SYMBOL_GPL(bio_brick_type);

////////////////// module init stuff /////////////////////////

static int __init init_bio(void)
{
	MARS_INF("init_bio()\n");
	_bio_brick_type = (void*)&bio_brick_type;
	return bio_register_brick_type();
}

static void __exit exit_bio(void)
{
	MARS_INF("exit_bio()\n");
	bio_unregister_brick_type();
}

MODULE_DESCRIPTION("MARS bio brick");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(init_bio);
module_exit(exit_bio);