/*
 * Copyright (c) 1998-2017 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2017 Stony Brook University
 * Copyright (c) 2003-2017 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "wrapfs.h"

/*
 * The inode cache is used with alloc_inode for both our inode info and the
 * vfs inode.
 */
static struct kmem_cache *wrapfs_inode_cachep;

/* final actions when unmounting a file system */
static void wrapfs_put_super(struct super_block *sb)
{
	struct wrapfs_sb_info *spd;
	struct super_block *s;

	spd = WRAPFS_SB(sb);
	if (!spd)
		return;

	/* decrement lower super references */
	s = wrapfs_lower_super(sb);
	wrapfs_set_lower_super(sb, NULL);
	atomic_dec(&s->s_active);

	kfree(spd);
	sb->s_fs_info = NULL;
}

static int wrapfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	int err;
	struct path lower_path;

	wrapfs_get_lower_path(dentry, &lower_path);
	err = vfs_statfs(&lower_path, buf);
	wrapfs_put_lower_path(dentry, &lower_path);

	/* set return buf to our f/s to avoid confusing user-level utils */
	buf->f_type = WRAPFS_SUPER_MAGIC;

	return err;
}

/*
 * @flags: numeric mount options
 * @options: mount options string
 */
static int wrapfs_remount_fs(struct super_block *sb, int *flags, char *options)
{
	int err = 0;
    kwal_init(sb);

	/*
	 * The VFS will take care of "ro" and "rw" flags among others.  We
	 * can safely accept a few flags (RDONLY, MANDLOCK), and honor
	 * SILENT, but anything else left over is an error.
	 */
	if ((*flags & ~(MS_RDONLY | MS_MANDLOCK | MS_SILENT)) != 0) {
		printk(KERN_ERR
		       "wrapfs: remount flags 0x%x unsupported\n", *flags);
		err = -EINVAL;
	}

	return err;
}

/*
 * Called by iput() when the inode reference count reached zero
 * and the inode is not hashed anywhere.  Used to clear anything
 * that needs to be, before the inode is completely destroyed and put
 * on the inode free list.
 */
static void wrapfs_evict_inode(struct inode *inode)
{
	struct inode *lower_inode;

#if 0
    struct wrapfs_inode_info *wi_target = WRAPFS_I(inode);
    struct commit_tree_list* target_ct;


//        trace_printk("start\n");
    trace_printk("[%lu]\n",inode->i_ino);

    down_write(&wi_target->redirection_tree_lock);
    target_ct = wi_target->commit_tree;
    if(target_ct != NULL){
        struct kwal_info* kwal_i = &(WRAPFS_SB(inode->i_sb)->kwal_info);
        int size;
        unsigned long *offset_array;
        struct file *kwal_file;
        struct redirection_entry *entry, *tentry;
        struct commit_tree_list * cl;
        int i;


        up_write(&wi_target->redirection_tree_lock);

//         trace_printk("[%lu]: c-tree check\n", inode->i_ino);

        if(target_ct->inode != inode){
            BUG();
//              trace_printk("target_ct error!\n");
        }

        // del commit tree entry
        down_write(&kwal_i->commit_tree_lock);
//            trace_printk("del_s\n");
        list_del_init(&target_ct->list);
//            trace_printk("del_e\n");
        up_write(&kwal_i->commit_tree_lock);
//      printk("ext4_destroy_inode\n");



        down_write(&wi_target->redirection_tree_lock);
        target_ct = wi_target->commit_tree; // reload
        if(target_ct == NULL)
        	goto end_evict_inode;
        if(target_ct->remap_length == 0){
//               trace_printk("[%lu]: len=0\n", inode->i_ino);
            wi_target->commit_tree = NULL;
            up_write(&wi_target->redirection_tree_lock);
            kfree(target_ct);
            goto end_evict_inode;
        }

//            mutex_lock(&kwal_i->atomic_mutex);


        offset_array = (unsigned long*)kmalloc(sizeof(unsigned long)*(target_ct->remap_length)*2, GFP_KERNEL);

        for(i=0; i<KWAL_NUM; i++){
            kwal_file = (struct file *) kwal_i->kwals[i]->kwal_file;
            size = 0;

            list_for_each_entry_safe(entry, tentry, &target_ct->kwal_list[i], neighbour){
                hash_del(&entry->node);
                list_del_init(&entry->neighbour);
                if(!list_empty(&entry->next_entry))
                    list_del(&entry->next_entry);
                offset_array[size++] = entry->org_block;
                offset_array[size++] = (entry->new_block) & 0x0FFFFFFFUL;

                kfree(entry);
            }
            list_del_init(&target_ct->kwal_list[i]);

            vfs_fsync(kwal_file, 0);
#ifdef F2FS_REMAP
            f2fs_remap_kwal(wrapfs_lower_inode(inode), offset_array, size/2, kwal_file);
#endif
#ifdef EXT4_EXT_REMAP
            remap_extent_kwal(wrapfs_lower_inode(inode), offset_array, size/2, kwal_file);
#endif
#ifdef EXT4_IND_REMAP
            remap_kwal(wrapfs_lower_inode(inode), offset_array, size/2, kwal_file);
#endif
#ifdef COPY_CP
#ifndef SEL_REMAP
            copy_kwal(inode, offset_array, size/2, kwal_file);
#endif
#endif

        }
        hash_init(target_ct->redirection_hash);
        wi_target->commit_tree = NULL;
        // make handle before calling remap_kwal()

        up_write(&wi_target->redirection_tree_lock);
        // before closing handle, journal metablock
//            mutex_unlock(&kwal_i->atomic_mutex);

        // log remapped information
    // log inode number, length = 0xFFFFFFFF

        kfree(offset_array);
        kfree(target_ct);

    }else{
        up_write(&wi_target->redirection_tree_lock);
    }
    end_evict_inode:


#endif
	truncate_inode_pages(&inode->i_data, 0);
	clear_inode(inode);
	/*
	 * Decrement a reference to a lower_inode, which was incremented
	 * by our read_inode when it was created initially.
	 */
	lower_inode = wrapfs_lower_inode(inode);
	wrapfs_set_lower_inode(inode, NULL);
	iput(lower_inode);
}

static struct inode *wrapfs_alloc_inode(struct super_block *sb)
{
	struct wrapfs_inode_info *i;

	i = kmem_cache_alloc(wrapfs_inode_cachep, GFP_KERNEL);
	if (!i)
		return NULL;

	/* memset everything up to the inode to 0 */
	memset(i, 0, offsetof(struct wrapfs_inode_info, vfs_inode));
	//DJ
	init_rwsem(&i->redirection_tree_lock);
	mutex_init(&i->atomic_mutex);
	i->commit_tree= NULL;
	i->kwal_isize = 0;
	i->time = 0;
	i->active_txs=0;
#ifdef COPY_CP
	i->i_file = NULL;
#endif
	i->vfs_inode.i_version = 1;
	return &i->vfs_inode;
}

static void wrapfs_destroy_inode(struct inode *inode)
{
	kmem_cache_free(wrapfs_inode_cachep, WRAPFS_I(inode));
}

/* wrapfs inode cache constructor */
static void init_once(void *obj)
{
	struct wrapfs_inode_info *i = obj;

	inode_init_once(&i->vfs_inode);
}

int wrapfs_init_inode_cache(void)
{
	int err = 0;

	wrapfs_inode_cachep =
		kmem_cache_create("wrapfs_inode_cache",
				  sizeof(struct wrapfs_inode_info), 0,
				  SLAB_RECLAIM_ACCOUNT, init_once);
	if (!wrapfs_inode_cachep)
		err = -ENOMEM;
	return err;
}

/* wrapfs inode cache destructor */
void wrapfs_destroy_inode_cache(void)
{
	if (wrapfs_inode_cachep)
		kmem_cache_destroy(wrapfs_inode_cachep);
}

/*
 * Used only in nfs, to kill any pending RPC tasks, so that subsequent
 * code can actually succeed and won't leave tasks that need handling.
 */
static void wrapfs_umount_begin(struct super_block *sb)
{
	struct super_block *lower_sb;

	lower_sb = wrapfs_lower_super(sb);
	if (lower_sb && lower_sb->s_op && lower_sb->s_op->umount_begin)
		lower_sb->s_op->umount_begin(lower_sb);
}

const struct super_operations wrapfs_sops = {
	.put_super	= wrapfs_put_super,
	.statfs		= wrapfs_statfs,
	.remount_fs	= wrapfs_remount_fs,
	.evict_inode	= wrapfs_evict_inode,
	.umount_begin	= wrapfs_umount_begin,
	.show_options	= generic_show_options,
	.alloc_inode	= wrapfs_alloc_inode,
	.destroy_inode	= wrapfs_destroy_inode,
	.drop_inode	= generic_delete_inode,
};

/* NFS support */

static struct inode *wrapfs_nfs_get_inode(struct super_block *sb, u64 ino,
					  u32 generation)
{
	struct super_block *lower_sb;
	struct inode *inode;
	struct inode *lower_inode;

	lower_sb = wrapfs_lower_super(sb);
	lower_inode = ilookup(lower_sb, ino);
	inode = wrapfs_iget(sb, lower_inode);
	return inode;
}

static struct dentry *wrapfs_fh_to_dentry(struct super_block *sb,
					  struct fid *fid, int fh_len,
					  int fh_type)
{
	return generic_fh_to_dentry(sb, fid, fh_len, fh_type,
				    wrapfs_nfs_get_inode);
}

static struct dentry *wrapfs_fh_to_parent(struct super_block *sb,
					  struct fid *fid, int fh_len,
					  int fh_type)
{
	return generic_fh_to_parent(sb, fid, fh_len, fh_type,
				    wrapfs_nfs_get_inode);
}

/*
 * all other funcs are default as defined in exportfs/expfs.c
 */

const struct export_operations wrapfs_export_ops = {
	.fh_to_dentry	   = wrapfs_fh_to_dentry,
	.fh_to_parent	   = wrapfs_fh_to_parent
};
