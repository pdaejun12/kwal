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


static int local_threshold = 5;
static int do_copy = 0;

int calc_time(struct timeval timeStart, struct timeval timeEnd, struct timeval *ret){

        ret->tv_sec  = timeEnd.tv_sec  - timeStart.tv_sec;
        ret->tv_usec = timeEnd.tv_usec - timeStart.tv_usec;
        if( ret->tv_usec < 0 )
        {
        	ret->tv_sec  = ret->tv_sec  - 1;
        	ret->tv_usec = ret->tv_usec + 1000000;
        }
}


int do_kwal_crash(struct kwal_info *kwal_i){
	struct commit_tree_list *cl;
	struct redirection_entry *entry;
	int i;

	//wrapfs_debug("loop start\n");
	down_write(&kwal_i->commit_tree_lock);

	// for each commit list
	list_for_each_entry(cl, &kwal_i->per_inode_commit_tree, list){
			struct wrapfs_inode_info *wi = WRAPFS_I(cl->inode);
			down_write(&wi->redirection_tree_lock);
			trace_printk("ino %u [%u]\n",cl->inode->i_ino, wi->kwal_isize);

			for (i=0; i< KWAL_NUM; i++){
				trace_printk("%d KWAL\n",i);
				hash_for_each(cl->redirection_hash,i,entry,node){
					trace_printk("%u:%u:%08X:%1d:%1d\n", entry->org_block,get_kwal_blk(entry->new_block),
							entry->cs,entry->dirt,entry->valid);
				}
			}

			up_write(&wi->redirection_tree_lock);
	}
	up_write(&kwal_i->commit_tree_lock);


	return 0;
}

#ifdef FINEWC_DETECT
void page_bitmap(u64* bitmap, unsigned long offset, unsigned long len)
{
#define BITUNIT (64)
	unsigned long pos1;
	unsigned long pos2;
	int i;

	wrapfs_debug("%lu %lu\n", offset, len);
	if(offset==0 && len==PAGE_SIZE){
		*bitmap = (u64)0xFFFFFFFFFFFFFFFF;
		return;
	}
	pos1 = offset / BITUNIT;
	pos2 = (offset + len - 1) / BITUNIT;
	*bitmap = 0;
	for(i=pos1; i<=pos2; i++)
		*bitmap |= ((u64)1<<i);
}


void get_dirtybitmap(u64 *bitmaplist, unsigned long pos, unsigned long len){
	unsigned long index, last_index, perpage_pos, perpage_len;
	int multipage=0;

	index = pos >> PAGE_SHIFT;
	last_index = (pos + len -1) >> PAGE_SHIFT;
	perpage_pos = pos & (PAGE_SIZE - 1);

	multipage = last_index - index;
	wrapfs_debug("pos:%lu len:%lu\n", pos, len);

	if(multipage == 0){
		//single partial page dirty
		wrapfs_debug("single page\n");
		page_bitmap(bitmaplist, pos, len);
		wrapfs_debug("0x%016llX\n", bitmaplist[0]);
	}else{
		int i;
		perpage_len = PAGE_SIZE - perpage_pos;
		wrapfs_debug("multi page\n");
		//multiple-page setting
		//first page is partial dirty
		for(i=0; i<=multipage; i++){
			page_bitmap(bitmaplist+i,perpage_pos,perpage_len);
			perpage_pos = 0;
			len -= perpage_len;
			perpage_len = len>=PAGE_SIZE? PAGE_SIZE:len;
			wrapfs_debug("0x%016llX\n", bitmaplist[i]);
		}
	}
}
#endif

#ifndef RR_ISO
struct redirection_entry* blk_redirection_closed_txs(struct commit_tree_list *cl, unsigned long org_blk, int now){
    struct redirection_entry *entry;
//    trace_printk("start\n");
    hash_for_each_possible(cl->redirection_hash,entry,node,org_blk){
          if(entry->org_block == org_blk){
   //         trace_printk("end 1\n");
            return entry;
          }
    }
//    trace_printk("end 2\n");
    return NULL;
}
#endif
#ifdef RR_ISO
struct redirection_entry* blk_redirection_closed_txs(struct commit_tree_list *cl, unsigned long org_blk, int now){
		struct redirection_entry *entry;
		struct redirection_entry *lentry;
		struct redirection_entry *this=NULL;
		int found = 0;
		int last_time = -2;

		if(cl==NULL)
				return NULL;

		//    wrapfs_debug("start\n");
		hash_for_each_possible(cl->redirection_hash,entry,node,org_blk){
				if(entry->org_block == org_blk){
						if(entry->endt <= now){
								if(last_time < entry->endt){
										last_time = entry->endt;
										this = entry;
										found++;
										wrapfs_debug("C1 [%lu] %d: %lu->%lu %d,%d\n", cl->ino, get_kwal_num(entry->new_block), get_kwal_blk(entry->org_block), get_kwal_blk(entry->new_block), entry->endt, now);
								}
						}else{
								wrapfs_debug("I1 [%lu] %d: %lu->%lu %d,%d\n", cl->ino, get_kwal_num(entry->new_block), get_kwal_blk(entry->org_block), get_kwal_blk(entry->new_block), entry->endt, now);
						}
						list_for_each_entry(lentry, &entry->next_version, next_version){
								if(lentry == entry)
										continue;
								if(lentry->endt <= now){
										if(last_time < lentry->endt){
												if(found){
														wrapfs_debug("C1 [%lu] %d: %lu->%lu %d,%d\n", cl->ino, get_kwal_num(this->new_block),
																		get_kwal_blk(this->org_block), get_kwal_blk(this->new_block), this->endt, now);
														found=0;
												}
												last_time = lentry->endt;
												this = lentry;
//												WARN_ON_ONCE(1);
												wrapfs_debug("C2 [%lu] %d: %lu->%lu %d,%d\n", cl->ino, get_kwal_num(this->new_block),
																get_kwal_blk(this->org_block), get_kwal_blk(this->new_block), this->endt, now);
										}
								}else{
										wrapfs_debug("I2 [%lu] %d: %lu->%lu %d,%d\n", cl->ino, get_kwal_num(lentry->new_block), get_kwal_blk(lentry->org_block), get_kwal_blk(lentry->new_block), lentry->endt, now);
								}
						}

				}
		}
		//    wrapfs_debug("end 2\n");

		//    if(this==NULL){
		//    	wrapfs_debug("E [%lu] %lu->NULL %d\n", cl->ino, org_blk, now);
		//    }

		return this;
}
#endif
struct redirection_entry* blk_redirection_ongoing_tx(struct wrapfs_file_info *filp, unsigned long org_blk){
		struct redirection_entry *entry;
		//    wrapfs_debug("start\n");
		hash_for_each_possible(filp->redirection_hash,entry,node,org_blk){
				if(entry->org_block == org_blk){
						//        wrapfs_debug("end 1\n");
						wrapfs_debug("%d: %lu->%lu\n",
										filp->lower_file->f_inode->i_ino,  entry->org_block, get_kwal_blk(entry->new_block));
						return entry;
				}
		}
		//   wrapfs_debug("end 2\n");
		return NULL;
}
#ifdef FINEWC_DETECT
int add_redirection_entry_staging_tree(struct commit_tree_list *cl, struct redirection_entry *p_rd, u64 dirtybitmap){
		struct staging_entry *entry;
		unsigned long org_blk, new_blk;
		int ret=0;

		org_blk = p_rd->org_block;
		new_blk = p_rd->new_block;

		if(p_rd->p_staging != NULL){
			//update dirtybitmap
			u64 old_dirtybitmap = dirtybitmap;
			wrapfs_debug("update dirty bitmap 0x%016llX, 0x%016llX\n",p_rd->p_staging->dirtybitmap, dirtybitmap);
			dirtybitmap &= ~(p_rd->p_staging->dirtybitmap);
			p_rd->p_staging->dirtybitmap |= old_dirtybitmap;
		}
		hash_for_each_possible(cl->staging_hash,entry,staging_node,org_blk){
			int found=0;
			if((entry->org_block == org_blk)&&(entry->new_block != new_blk)){
				// block-level conflict detected
				struct conflict_entry *c_entry;
				hash_for_each_possible(cl->conflict_hash,c_entry,conflict_node,org_blk){
					if(c_entry->org_block == org_blk){
						// block-level conflict exist
						found=1;
						if((c_entry->dirtybitmap & dirtybitmap) == 0ULL){
							// NO 64B-level conflict
							wrapfs_debug("case1 0x%016llX, 0x%016llX\n",c_entry->dirtybitmap, dirtybitmap);
							c_entry->dirtybitmap |= dirtybitmap;
							goto _64B_conflict_checked;
						}
						else{
							// 64B-level conflict
							trace_printk("conflict1 0x%016llX:0x%016llX ino:%d, %lu->%lu,%lu\n",
									c_entry->dirtybitmap, dirtybitmap,
									cl->ino, org_blk, get_kwal_blk(entry->p_redentry->new_block),
									get_kwal_blk(p_rd->new_block));
//							WARN_ON(1);
							ret = 1;
						}
					}
				}
				if(found==0){
					// block-level conflict information is not exist
					// add new conflict node
					c_entry = (struct conflict_entry *)kmalloc(sizeof(struct conflict_entry), GFP_KERNEL);
					// entry is another conflict block
					c_entry->dirtybitmap = entry->dirtybitmap;
					c_entry->org_block = org_blk;
					INIT_HLIST_NODE(&c_entry->conflict_node);
					hash_add(cl->conflict_hash,&c_entry->conflict_node,org_blk);

					if((c_entry->dirtybitmap & dirtybitmap) == 0ULL){
						// NO 64B-level conflict
						wrapfs_debug("case2 0x%016llX, 0x%016llX\n",c_entry->dirtybitmap, dirtybitmap);
						c_entry->dirtybitmap |= dirtybitmap;
						goto _64B_conflict_checked;
					}
					else{
						// 64B-level conflict
						trace_printk("conflict2 0x%016llX:0x%016llX ino:%d, %lu->%lu,%lu\n",
								c_entry->dirtybitmap, dirtybitmap,
								cl->ino, org_blk, get_kwal_blk(entry->p_redentry->new_block),
								get_kwal_blk(p_rd->new_block));
//						WARN_ON(1);
						ret = 1;
					}
				}
				// setting conflict flag on another entry
				entry->p_redentry->is_conflict = 1;
				p_rd->is_conflict = 1; // new entry conflict value
				wrapfs_debug("Add conflict ino:%d(%lu) %lu,%lu\n",
						cl->ino, org_blk, get_kwal_blk(entry->p_redentry->new_block),
						get_kwal_blk(p_rd->new_block));
			}
		}

_64B_conflict_checked:

		if(p_rd->p_staging != NULL){
			wrapfs_debug("no additional staging entry ino:%d, %lu->%lu\n", cl->ino, org_blk,  get_kwal_blk(p_rd->new_block));
			return ret;
		}

		entry = (struct staging_entry *)kmalloc(sizeof(struct staging_entry), GFP_KERNEL);
		//  wrapfs_debug("M [%X]\n",entry);
		wrapfs_debug("ino:%d(%lu) %lu\n", cl->ino, org_blk,  get_kwal_blk(p_rd->new_block));
		if(entry == NULL){
				wrapfs_debug("bug\n");
				printk("no mem alloc\n");
		}
		entry->org_block = org_blk;
		entry->new_block = new_blk;
		entry->p_redentry = p_rd;
		entry->dirtybitmap = dirtybitmap;
		p_rd->p_staging = entry;
		INIT_HLIST_NODE(&entry->staging_node);
		hash_add(cl->staging_hash,&entry->staging_node,org_blk);
		return ret;
}
#endif
int add_redirection_entry_closed_txs(struct commit_tree_list *cl, unsigned long org_blk, unsigned long new_blk, u32 cs, int now){
		struct redirection_entry *entry;
		struct redirection_entry *tentry;
		struct redirection_entry *old_entry=NULL;
		int ret = 1;
		//    wrapfs_debug("start\n");
		hash_for_each_possible_safe(cl->redirection_hash,entry,tentry,node,org_blk){
			if(entry->org_block == org_blk){
				// multiversion support
#ifdef RR_ISO
				if(entry->valid == 0){
						BUG();
				}
				wrapfs_debug("D [%lu] %lu->%lu %d\n", cl->ino, get_kwal_blk(entry->org_block), get_kwal_blk(entry->new_block), entry->endt);
				if(entry->dirt == 1)
					cl->length--;
				entry->valid = 0;
				entry->dirt = 0;
				hash_del(&entry->node);
				list_add_tail(&entry->gc_entry, &cl->gc_list);
				list_del_init(&entry->next_active);
				list_del_init(&entry->next_entry);
				list_del_init(&entry->neighbour);
				old_entry = entry;
				ret = 0;
#else
				if(entry->dirt)
					ret=0;
	       		entry->new_block = new_blk;
				entry->dirt = 1;
			    entry->cs = cs;
	            if(!list_empty(&entry->next_entry))
	                list_del_init(&entry->next_entry);
	            list_add(&entry->next_entry,&cl->dirty_listhead);
	            if(!list_empty(&entry->neighbour))
	                list_del_init(&entry->neighbour);
	            list_add_tail(&entry->neighbour, &cl->kwal_list[get_kwal_num(entry->new_block)]);
	            cl->length += ret;
	            return ret;
#endif
			}



		}
		entry = (struct redirection_entry *)kmalloc(sizeof(struct redirection_entry), GFP_KERNEL);
		//  wrapfs_debug("M [%X]\n",entry);

		if(entry == NULL){
				wrapfs_debug("bug\n");
				printk("no mem alloc\n");
		}
		entry->new_block = new_blk;
		entry->org_block = org_blk;
		entry->dirt = 1;
		entry->valid = 1;
		entry->cs = cs;
#ifdef RR_ISO
		entry->endt = now;
#endif
		list_add_tail(&entry->next_entry,&cl->dirty_listhead);
		wrapfs_debug("N [%lu] %lu->%lu\n",cl->ino, entry->org_block
				, get_kwal_blk(entry->new_block));
		//    wrapfs_debug("%lu %lu 0x%X\n", get_kwal_blk(entry->org_block), get_kwal_blk(entry->new_block), cs);
		INIT_LIST_HEAD(&entry->neighbour);

#ifdef RR_ISO
		INIT_LIST_HEAD(&entry->gc_entry);
		INIT_LIST_HEAD(&entry->next_version);
		INIT_LIST_HEAD(&entry->next_active);
#endif

		INIT_HLIST_NODE(&entry->node);
		hash_add(cl->redirection_hash,&entry->node,org_blk);
		list_add_tail(&entry->neighbour, &cl->kwal_list[get_kwal_num(entry->new_block)]);
#ifdef RR_ISO
		list_add_tail(&entry->next_active, &cl->active_entry_head);
#endif
		cl->length++;
#ifdef RR_ISO
		if(old_entry)
				list_add(&entry->next_version, &old_entry->next_version);
#endif
		//    wrapfs_debug("end 2\n");
		return ret;
}



struct redirection_entry* add_redirection_entry_ongoing_tx(struct wrapfs_file_info *filp, unsigned long org_blk, unsigned long new_blk, u32 cs){
		struct redirection_entry *entry;
		//    wrapfs_debug("start\n");

		hash_for_each_possible(filp->redirection_hash,entry,node,org_blk){
				if(entry->org_block == org_blk){
						wrapfs_debug("[%lu] %d:%lu -> %d:%lu\n",entry->org_block,
										get_kwal_num(entry->new_block), get_kwal_blk(entry->new_block),
										get_kwal_num(new_blk), get_kwal_blk(new_blk));
						entry->new_block = new_blk;
						entry->cs = cs;
						entry->dirt = 1;
						//           wrapfs_debug("end 1\n");
						return entry;
				}
		}
		entry = (struct redirection_entry *)kmalloc(sizeof(struct redirection_entry), GFP_KERNEL);
		//  wrapfs_debug("M [%X]\n",entry);
		if(entry == NULL){
				wrapfs_debug("bug\n");
				printk("no mem alloc\n");
				BUG();
		}
		entry->new_block = new_blk;
		entry->org_block = org_blk;
		entry->dirt = 1;
		entry->cs = cs;
#ifdef FINEWC_DETECT
		entry->is_conflict = 0;
		entry->p_staging = NULL;
#endif
		wrapfs_debug("[%lu] %lu->%lu\n",filp->lower_file->f_inode->i_ino,
				entry->org_block, get_kwal_blk(entry->new_block));
		INIT_LIST_HEAD(&entry->neighbour);
		INIT_HLIST_NODE(&entry->node);
		hash_add(filp->redirection_hash,&entry->node,org_blk);
		list_add_tail(&entry->next_entry,&filp->traversing_listhead);
		//   wrapfs_debug("end 2\n");
		return entry;
}


#include <linux/freezer.h>
#include <linux/kthread.h>

struct commit_tree_list * init_commit_tree(struct kwal_info *kwal_i, struct wrapfs_inode_info *wi){
		struct commit_tree_list *ct;

		ct = wi->commit_tree;
		//no commit tree for given inode
		if(ct == NULL){
				int i;
				ct = (struct commit_tree_list *)kmalloc(sizeof(struct commit_tree_list), GFP_KERNEL);
				ct->inode = &wi->vfs_inode;
				ct->ino = wi->vfs_inode.i_ino;
				ct->length = 0;
				ct->remap_length = 0;
				ct->written_length = 0;

				hash_init(ct->redirection_hash);
#ifdef FINEWC_DETECT
				hash_init(ct->staging_hash);
				hash_init(ct->conflict_hash);
#endif
				INIT_LIST_HEAD(&ct->list);
				INIT_LIST_HEAD(&ct->dirty_listhead);
				INIT_LIST_HEAD(&ct->active_entry_head);
				INIT_LIST_HEAD(&ct->gc_list);
				for(i=0; i<KWAL_NUM; i++)
						INIT_LIST_HEAD(&ct->kwal_list[i]);

				wi->commit_tree = ct;
				up_write(&wi->redirection_tree_lock);

				down_write(&kwal_i->commit_tree_lock);
				list_add(&ct->list, &kwal_i->per_inode_commit_tree);
				up_write(&kwal_i->commit_tree_lock);
				down_write(&wi->redirection_tree_lock);
		}
		return ct;
}


int write_kwal_metadata(struct file *fp, char *buf, unsigned long long offset){
#if 0
		mm_segment_t old_fs;
		int ret;
		wrapfs_debug("start\n");
		offset *= PAGE_SIZE;    
		old_fs = get_fs();
		set_fs(get_ds());
		ret = __vfs_write(fp, (const char __user *)buf, PAGE_SIZE, &offset);
		if(ret<0){
				printk("error %d\n", ret);
				BUG();
		}
		set_fs(old_fs);
		wrapfs_debug("end\n");
		return 0;
#endif
		offset *= PAGE_SIZE;
		return __kernel_write(fp, buf, PAGE_SIZE, &offset);
}

#ifdef FINEWC_DETECT
u32 write_from_dirtybitmap(struct file * kwal_file, unsigned long org_blk, unsigned long new_blk, u64 bitmap){
		struct inode* kwal_inode = file_inode(kwal_file);
		int i;
		int cnt=0;
		loff_t pos;
		struct page *kwal_page;
		char buf[PAGE_SIZE], old_buf[PAGE_SIZE];
		char *tmp;
		u32 ret;

		kwal_page = read_cache_page(kwal_file->f_mapping, org_blk, (filler_t *)kwal_file->f_mapping->a_ops->readpage, NULL);
		tmp = kmap_atomic(kwal_page);
		memcpy(buf, tmp, PAGE_SIZE);
		kunmap_atomic(tmp);
		put_page(kwal_page);

		kwal_page = read_cache_page(kwal_file->f_mapping, new_blk, (filler_t *)kwal_file->f_mapping->a_ops->readpage, NULL);
		tmp = kmap_atomic(kwal_page);
		memcpy(old_buf, tmp, PAGE_SIZE);
		kunmap_atomic(tmp);
		put_page(kwal_page);

		for(i=0; i<PAGE_SIZE/BITUNIT; i++){
			if(bitmap & ((u64)1<<i)){
				if(cnt==0)
					pos=i*BITUNIT;
				cnt+=BITUNIT;
			}
			else if(cnt!=0){
				wrapfs_debug("%lu+%d\n", pos, cnt);
				memcpy(&buf[pos], &old_buf[pos], cnt);
				cnt=0;
			}
		}
		write_kwal_metadata(kwal_file, buf, new_blk);
		ret = crc32(0, buf, PAGE_SIZE);
		return ret;
}
#endif


#if 0
static int kwalGCd(void *arg){
		struct kwal_info * kwal_i = (struct kwal_info *)arg;
		struct file *kwal_index_file, *kwal_old_index_file;
		struct inode *kwal_index_inode, *kwal_old_index_inode;
		char *buf;
		int err;
		char *mb_p;
		__be32 *mb;
		struct commit_tree_list *cl;
		struct kwal_node *kwal_index_node, *kwal_old_index_node;
		struct redirection_entry *entry, *tentry;
		int i;
		int offset;

		set_freezable();

		buf = (char *)kmalloc(PAGE_SIZE, GFP_KERNEL);
		kwal_i->gc_trigger = 0;
		wake_up(&kwal_i->gc_done);

		//    spin_lock(&kwal_i->gc_lock); // it might be removed

gc_loop:
		if(kwal_i->gc_trigger == 1){

				wrapfs_debug("gc start\n");
				spin_lock(&kwal_i->curr_index_lock);
				kwal_old_index_node = kwal_i->kwal_index;

				if(kwal_old_index_node == kwal_i->kwal_indexes[0])
						kwal_i->kwal_index = kwal_i->kwal_indexes[1];
				else
						kwal_i->kwal_index = kwal_i->kwal_indexes[0];
				spin_unlock(&kwal_i->curr_index_lock);

				kwal_old_index_file = (struct file*) kwal_old_index_node->kwal_file;
				kwal_old_index_inode = file_inode(kwal_old_index_file);

				kwal_index_node = kwal_i->kwal_index;
				kwal_index_file = (struct file*) kwal_index_node->kwal_file;
				kwal_index_inode = file_inode(kwal_index_file);


				/* no trucate!
				   truncate_setsize(kwal_index_inode, 0);
				   ext4_truncate(kwal_index_inode);
				 */
				spin_lock(&kwal_index_node->last_block_lock);
				kwal_index_node->last_block = 0;
				spin_unlock(&kwal_index_node->last_block_lock);

				memset(buf, 0, PAGE_SIZE);
				mb_p = (char*)buf;
				offset = 0;


				down_read(&kwal_i->commit_tree_lock);
				// for each commit list
				list_for_each_entry(cl, &kwal_i->per_inode_commit_tree, list){
						struct wrapfs_inode_info *wi = WRAPFS_I(cl->inode);

						//           wrapfs_debug("[%lu]: log c-tree\n", cl->inode->i_ino);

						// size of remap entries for an inode exceeds PAGE_SIZE
						if(PAGE_SIZE < ((cl->length+1) * 2 * sizeof(__be32))){
								// do special thing
								// seperating commit tree with same inode number
								//          wrapfs_debug("do special thing [%s]\n",target_file->f_dentry->d_name.name);
						}

						// metablock is full with redirection entry
						if(PAGE_SIZE < (offset + (4 * sizeof(__be32)))){
								//we shoud go next block

								//                wrapfs_debug("metablock is full A part\n");
								//erase 0 enrty
								mb_p -= sizeof(__be32);
								offset -= sizeof(__be32);
								if(offset > PAGE_SIZE)
										BUG();
								write_kwal_metadata(kwal_index_file, buf, kwal_index_node->last_block);

								spin_lock(&kwal_index_node->last_block_lock);
								kwal_index_node->last_block++;
								spin_unlock(&kwal_index_node->last_block_lock);

								memset(buf, 0, PAGE_SIZE);
								mb_p = (char*)buf;
								offset = 0;
						}

						mb = (__be32 *)mb_p;
						*mb = cpu_to_be32(cl->inode->i_ino);
						mb_p += sizeof(__be32);
						offset += sizeof(__be32);

						mb = (__be32 *)mb_p;
						*mb = cpu_to_be32(cl->length);
						mb_p += sizeof(__be32);
						offset += sizeof(__be32);

						down_write(&wi->redirection_tree_lock);

						hash_for_each(cl->redirection_hash,i,entry,node){
								if(!list_empty(&entry->next_entry))
										list_del_init(&entry->next_entry);
								entry->dirt = 0;
								mb = (__be32 *)mb_p;
								*mb = cpu_to_be32(entry->org_block);
								mb_p += sizeof(__be32);
								offset += sizeof(__be32);

								mb = (__be32 *)mb_p;
								*mb = cpu_to_be32(entry->new_block);
								mb_p += sizeof(__be32);
								offset += sizeof(__be32);

								if((offset + (sizeof(__be32)*4)) > PAGE_SIZE){
										//                   wrapfs_debug("metablock is full B part\n");
										if(offset > PAGE_SIZE)
												BUG();
										write_kwal_metadata(kwal_index_file, buf, kwal_index_node->last_block);

										spin_lock(&kwal_index_node->last_block_lock);
										kwal_index_node->last_block++;
										spin_unlock(&kwal_index_node->last_block_lock);

										memset(buf, 0, PAGE_SIZE);
										mb_p = (char*)buf;
										offset = 0;
								}
						}
						up_write(&wi->redirection_tree_lock);

						mb = (__be32 *)mb_p;
						*mb = cpu_to_be32(wi->kwal_isize);
						mb_p += sizeof(__be32);
						offset += sizeof(__be32);


						// if metablock is not full
						mb = (__be32 *)mb_p;
						*mb = cpu_to_be32(0x0);
						mb_p += sizeof(__be32);
						offset += sizeof(__be32);
				}
				up_read(&kwal_i->commit_tree_lock);

				//erase 0 enrty
				mb_p -= sizeof(__be32);

				//terminal char
				mb = (__be32 *)mb_p;
				*mb = cpu_to_be32(0xFFFFFFFF);
				mb_p += sizeof(__be32);


				write_kwal_metadata(kwal_index_file, buf, kwal_index_node->last_block);

				spin_lock(&kwal_index_node->last_block_lock);
				kwal_index_node->last_block++;
				spin_unlock(&kwal_index_node->last_block_lock);

				vfs_fallocate(kwal_index_file, 0, 0, KWAL_SIZE);
				vfs_fsync(kwal_index_file, 0);

				wrapfs_debug("end\n");
		}

		//sleep
		if (freezing(current)) {
				//        spin_unlock(&kwal_i->gc_lock);
				try_to_freeze();
				//        spin_lock(&kwal_i->gc_lock);
		} else {
				DEFINE_WAIT(wait);
				prepare_to_wait(&kwal_i->gc_done, &wait,
								TASK_INTERRUPTIBLE);
				//        spin_unlock(&kwal_i->gc_lock);
				schedule();
				//        spin_lock(&kwal_i->gc_lock);
				finish_wait(&kwal_i->gc_done, &wait);
		}
		goto gc_loop;

		kfree(buf);
		return 0;
}
#endif

static int kwal_wait_tx_end_atomic_t(atomic_t *a)
{
		schedule();
		return 0;
}

#ifdef COPY_CP
void copy_kwal(struct inode *target_inode,unsigned long * offset_array,int size,struct file * wal_file){
		struct file* target_file = WRAPFS_I(target_inode)->i_file;
		struct inode* temp_inode = file_inode(wal_file);
		int i;
		int direct =0;
		//read page
		filler_t *filler = (filler_t *)wal_file->f_mapping->a_ops->readpage;

		if(target_file == NULL)
				BUG();

		inode_lock(target_inode);
		inode_lock(temp_inode);
		if(target_file->f_flags & O_DIRECT){
				direct = 1;
				target_file->f_flags &= ~O_DIRECT;
		}

//		trace_printk("target ino[%d] +%d\n", target_inode->i_ino, size);
		for(i=0; i<size; i++){
				pgoff_t target_idx, wal_idx;
				struct page *wal_page;
				char *buf;
				int cs,ret;

				target_idx = offset_array[i*2];
				wal_idx = offset_array[i*2+1];
				wal_page = read_cache_page(wal_file->f_mapping, wal_idx, filler, NULL);


//				trace_printk("%lu %lu\n", target_idx, target_idx);
				if (!IS_ERR(wal_page))
						if (PageError(wal_page))
								BUG();
				buf = kmap_atomic(wal_page);

				cs = crc32(0, buf, PAGE_SIZE);

				ret = write_kwal_metadata(target_file, buf, target_idx);

				kunmap_atomic(buf);
				put_page(wal_page);

		}
		if(direct){
				target_file->f_flags |= O_DIRECT;
		}
		inode_unlock(target_inode);
		inode_unlock(temp_inode);
//		vfs_fsync(target_file, 1);
		return;
}
#endif

static int remapd(void *arg){
	struct kwal_info *kwal_i = arg;
	int i;
	char *buf;

	set_freezable();

	buf = (char *)kmalloc(PAGE_SIZE, GFP_KERNEL);
	kwal_i->remap_trigger = 0;
	wake_up(&kwal_i->remap_done);

	//    spin_lock(&kwal_i->remap_lock);

remap_loop:
	if(kwal_i->remap_trigger == 1){
			struct commit_tree_list *cl, *tcl;
			struct kwal_node *remap_kwal_node, *curr_kwal_node;
			struct file *kwal_file, *curr_kwal_file;
			struct inode *kwal_inode;
			struct redirection_entry *entry, *tentry;
			char *mb_p;
			__be32 *mb;
			__be64 *mb2;
			int frag;
			int err;
			int offset;
			unsigned long long curr_metablock;
			int remap_cnt, copy_cnt;
#ifdef CORSE_SEL
			int do_remap_ctrl=1;
#endif
			spin_lock(&kwal_i->curr_kwal_lock);
			remap_kwal_node = kwal_i->to_remap_kwal;
			curr_kwal_node = kwal_i->curr_kwal;
			kwal_i->to_remap_kwal = NULL;
			spin_unlock(&kwal_i->curr_kwal_lock);

			kwal_file = (struct file*)remap_kwal_node->kwal_file;
			kwal_inode = file_inode(kwal_file);

			trace_printk("[LAT] remap start %d\n",remap_kwal_node->num);
			wait_on_atomic_t(&remap_kwal_node->inflight_txs,
							kwal_wait_tx_end_atomic_t,
							TASK_UNINTERRUPTIBLE);

			trace_printk("written %llu blocks\n", remap_kwal_node->last_block);

			down_write(&remap_kwal_node->on_io);
			//
			// redirection table migration start
			//

			remap_cnt = 0;
			copy_cnt = 0;

			curr_kwal_file = (struct file *)curr_kwal_node->kwal_file;
#ifndef NO_META
			spin_lock(&curr_kwal_node->last_block_lock);
			curr_metablock = curr_kwal_node->index_block;
#ifndef SEQ_META
			curr_kwal_node->index_block--;
			curr_kwal_node->remained = curr_kwal_node->index_block - curr_kwal_node->last_block;
			if(curr_kwal_node->remained < 0){
					spin_unlock(&curr_kwal_node->last_block_lock);
					BUG();
			}
#else
			curr_kwal_node->index_block = curr_kwal_node->last_block++;
#endif
			spin_unlock(&curr_kwal_node->last_block_lock);
#endif
			memset(buf, 0, PAGE_SIZE);
			mb_p = (char*)buf;
			offset = 0;


			down_read(&kwal_i->commit_tree_lock);
			// for each commit list
			list_for_each_entry(cl, &kwal_i->per_inode_commit_tree, list){
					struct wrapfs_inode_info *wi = WRAPFS_I(cl->inode);
					int red_length;
					wrapfs_debug("ino [%lu] start\n", cl->ino);

					// size of remap entries for an inode exceeds PAGE_SIZE
					if(PAGE_SIZE < ((cl->length+1) * 2 * sizeof(__be32))){
							// do special thing
							// Separating commit tree with same inode number
							//          wrapfs_debug("do special thing [%s]\n",target_file->f_dentry->d_name.name);
					}

					// metablock is full with redirection entry
					if(PAGE_SIZE < (offset + (5 * sizeof(__be32)))){
							//go next block

							//                wrapfs_debug("metablock is full A part\n");
							//erase 0 entry
							mb_p -= sizeof(__be32);
							offset -= sizeof(__be32);
							if(offset > PAGE_SIZE)
									BUG();

#ifndef NO_META
							write_kwal_metadata(curr_kwal_file, buf, curr_metablock);

							spin_lock(&curr_kwal_node->last_block_lock);
							curr_metablock = curr_kwal_node->index_block;
#ifndef SEQ_META
							curr_kwal_node->index_block--;
							curr_kwal_node->remained = curr_kwal_node->index_block - curr_kwal_node->last_block;
							if(curr_kwal_node->remained < 0){
									spin_unlock(&curr_kwal_node->last_block_lock);
									BUG();
							}
#else
							curr_kwal_node->index_block = curr_kwal_node->last_block++;
#endif
							spin_unlock(&curr_kwal_node->last_block_lock);
#endif
							memset(buf, 0, PAGE_SIZE);
							mb_p = (char*)buf;
							offset = 0;
					}

					mb = (__be32 *)mb_p;
					*mb = cpu_to_be32(cl->inode->i_ino);
					mb_p += sizeof(__be32);
					offset += sizeof(__be32);


					down_write(&wi->redirection_tree_lock);
					red_length=0;
					hash_for_each(cl->redirection_hash,i,entry,node){
						red_length++;
					}

					mb = (__be32 *)mb_p;
					*mb = cpu_to_be32(red_length);
					mb_p += sizeof(__be32);
					offset += sizeof(__be32);

					wrapfs_debug("hash lock\n");
					hash_for_each(cl->redirection_hash,i,entry,node){
							if(!list_empty(&entry->next_entry))
									list_del_init(&entry->next_entry);
							entry->dirt = 0;
							mb = (__be32 *)mb_p;
							*mb = cpu_to_be32(entry->org_block);
							mb_p += sizeof(__be32);
							offset += sizeof(__be32);

							mb = (__be32 *)mb_p;
							*mb = cpu_to_be32(entry->new_block);
							mb_p += sizeof(__be32);
							offset += sizeof(__be32);

							mb = (__be32 *)mb_p;
							*mb = cpu_to_be32(entry->cs);
							mb_p += sizeof(__be32);
							offset += sizeof(__be32);

							if((offset + (sizeof(__be32)*5)) > PAGE_SIZE){
									//                   wrapfs_debug("metablock is full B part\n");
									if(offset > PAGE_SIZE)
											BUG();
#ifndef NO_META
									write_kwal_metadata(curr_kwal_file, buf, curr_metablock);

									spin_lock(&curr_kwal_node->last_block_lock);
									curr_metablock = curr_kwal_node->index_block;
#ifndef SEQ_META
									curr_kwal_node->index_block--;
									curr_kwal_node->remained = curr_kwal_node->index_block - curr_kwal_node->last_block;
									if(curr_kwal_node->remained < 0){
											spin_unlock(&curr_kwal_node->last_block_lock);
											BUG();
									}

#else
									curr_kwal_node->index_block = curr_kwal_node->last_block++;
#endif
									spin_unlock(&curr_kwal_node->last_block_lock);
#endif
									memset(buf, 0, PAGE_SIZE);
									mb_p = (char*)buf;
									offset = 0;
							}
					}
					up_write(&wi->redirection_tree_lock);
					wrapfs_debug("hash unlock\n");
					mb2 = (__be64 *)mb_p;
					*mb2 = cpu_to_be64(wi->kwal_isize);
					mb_p += sizeof(__be64);
					offset += sizeof(__be64);


					// if metablock is not full
					mb = (__be32 *)mb_p;
					*mb = cpu_to_be32(0x0);
					mb_p += sizeof(__be32);
					offset += sizeof(__be32);

					wrapfs_debug("ino [%lu] end\n", cl->ino);
			}
			up_read(&kwal_i->commit_tree_lock);

			//erase 0 enrty
			mb_p -= sizeof(__be32);

			//terminal char
			mb = (__be32 *)mb_p;
			*mb = cpu_to_be32(0xFFFFFFFF);
			mb_p += sizeof(__be32);

#ifndef NO_META
			write_kwal_metadata(curr_kwal_file, buf, curr_metablock);

			spin_lock(&curr_kwal_node->last_block_lock);
			curr_metablock = curr_kwal_node->index_block;

#ifndef SEQ_META
			curr_kwal_node->index_block--;
			curr_kwal_node->remained = curr_kwal_node->index_block - curr_kwal_node->last_block;
			if(curr_kwal_node->remained < 0){
					spin_unlock(&curr_kwal_node->last_block_lock);
					BUG();
			}
#else
			curr_kwal_node->index_block = curr_kwal_node->last_block++;
#endif
			spin_unlock(&curr_kwal_node->last_block_lock);
#endif
			// migration end

			// do checkpointing processing

			kwal_i->remap_trigger = 0;

            vfs_fsync(kwal_file, 0);

            down_write(&kwal_i->commit_tree_lock);
#ifdef CORSE_SEL
            //TODO start
            {
            	int nextent = 0;
            	int ext_cnt = 0;
            	int validity;
            	int written_length = 0;
            	int remap_length = 0;
            	int tot_size=0;
            	int size;
            	list_for_each_entry(cl, &kwal_i->per_inode_commit_tree, list){

            		unsigned long last_org, last_wal;
            		struct wrapfs_inode_info *wi = WRAPFS_I(cl->inode);

            		down_read(&wi->redirection_tree_lock);


            		if(cl->remap_length == 0){
            			up_write(&wi->redirection_tree_lock);
            			continue;
            		}

            		written_length += cl->written_length;
            		remap_length += cl->remap_length;
            		size = 0;
            		trace_printk("[%lu] %d %d\n", cl->inode->i_ino, cl->remap_length, cl->written_length);
    				nextent++;
            		list_for_each_entry(entry, &cl->kwal_list[remap_kwal_node->num], neighbour){
            			if (size==0 ||
            					((size > 0) && (last_org - 1 == entry->org_block)
            							&& (last_wal - 1 == get_kwal_blk(entry->new_block)))
										|| ((size > 0) && (last_org + 1 == entry->org_block)
												&& (last_wal + 1
														== get_kwal_blk(entry->new_block)))) {
            				;
            			} else {
            				nextent++;
            			}
            			size++;
                		last_org = entry->org_block;
                		last_wal = get_kwal_blk(entry->new_block);
            		}
            		up_read(&wi->redirection_tree_lock);
            		tot_size += size;
            	}
				ext_cnt = tot_size/nextent;
        		if(written_length == 0)
        			validity = 0;
        		else
        			validity = (100*remap_length)/written_length;
				trace_printk("[KWAL_R_CHECK] %d %d\n", validity, ext_cnt);
/*
				if(FORCE_COPY_VALIDITY > validity){
					//do copy
					do_remap_ctrl=0;
				} else
				*/
				if((validity > FORCE_REMAP_VALIDITY) || ((validity > REMAP_VALIDITY)&&(ext_cnt>=MIN_REMAP))){
					//do remap
					do_remap_ctrl=1;
				} else {
					//do copy
					do_remap_ctrl=0;
				}

            }
            //TODO end
#endif

            list_for_each_entry_safe(cl, tcl, &kwal_i->per_inode_commit_tree, list){
            	struct wrapfs_inode_info *wi = WRAPFS_I(cl->inode);
            	int size;
            	unsigned long *offset_array;
            	unsigned long last_org, last_wal;
            	struct redirection_entry *entry, *tentry;
            	int nextent = 1;
            	int ext_cnt = 0;
            	int validity;

            	wrapfs_debug("[%lu]: remap\n", cl->inode->i_ino);

            	down_write(&wi->redirection_tree_lock);

            	if(cl->remap_length == 0){
            		wrapfs_debug("[%lu]: len=0\n", cl->inode->i_ino);
            		hash_for_each_safe(cl->redirection_hash,i,tentry,entry,node){
            			list_del_init(&entry->neighbour);
            			list_del_init(&entry->next_active);
            			if(!list_empty(&entry->next_entry))
            				list_del(&entry->next_entry);
            			hash_del(&entry->node);
            			kfree(entry);
            		}
            		hash_init(cl->redirection_hash);
            		wi->commit_tree = NULL;
            		list_del(&(cl->list));
            		kfree(cl);
            		up_write(&wi->redirection_tree_lock);
            		continue;
            	}

            	offset_array = (unsigned long*)kmalloc(sizeof(unsigned long)*(cl->remap_length)*2, GFP_KERNEL);
            	wrapfs_debug("[%lu] remap length %d\n", cl->inode->i_ino, cl->remap_length);
            	trace_printk("[%lu] %d %d\n", cl->inode->i_ino, cl->remap_length, cl->written_length);
            	if(cl->written_length == 0)
            		validity = 0;
            	else
            		validity = (100*cl->remap_length)/cl->written_length;
            	cl->written_length =0;

            	size = 0;

            	list_for_each_entry_safe(entry, tentry, &cl->kwal_list[remap_kwal_node->num], neighbour){
            		hash_del(&entry->node);
            		list_del_init(&entry->neighbour);
#ifdef RR_ISO
            		list_del_init(&entry->next_active);
#endif
            		if(!list_empty(&entry->next_entry))
            			list_del(&entry->next_entry);

            		if (size==0 ||
            				((size > 0) && (last_org - 1 == entry->org_block)
            						&& (last_wal - 1 == get_kwal_blk(entry->new_block)))
									|| ((size > 0) && (last_org + 1 == entry->org_block)
											&& (last_wal + 1
													== get_kwal_blk(entry->new_block)))) {
            			;
            			//						trace_printk("[CP] %d %d\n", entry->org_block, get_kwal_blk(entry->new_block));
            		} else {
            			//						trace_printk("[CP] %d %d + %d\n", offset_array[size-2], offset_array[size-1], ext_cnt);
            			nextent++;
            		}
            		offset_array[size++] = entry->org_block;
            		offset_array[size++] = get_kwal_blk(entry->new_block);

            		last_org = entry->org_block;
            		last_wal = get_kwal_blk(entry->new_block);

            		//              trace_printk("[SEQ] %lu %lu\n", entry->org_block, get_kwal_blk(entry->new_block));

            		kfree(entry);
            		cl->remap_length--;
            	}
            	list_del_init(&cl->kwal_list[remap_kwal_node->num]);

#ifdef SEL_REMAP
            	if (size != 0) {

#ifdef CORSE_SEL
            		if(do_remap_ctrl){
            			//do remap
            			remap_extent_kwal(wrapfs_lower_inode(cl->inode),
            					offset_array, size / 2, kwal_file);
            			remap_cnt += size / 2;
            		}else{
            			copy_kwal(cl->inode, offset_array, size / 2, kwal_file);
            			copy_cnt += size / 2;
            		}
#else
            		ext_cnt = size/2/nextent;
            		trace_printk("[R_CHECK] %d %d\n", validity, ext_cnt);


            		wrapfs_debug("[CP] %d %d + %d\n", offset_array[size-2], offset_array[size-1], ext_cnt);
#ifdef SEL_REMAP
            		if(FORCE_COPY_VALIDITY > validity){
            			copy_kwal(cl->inode, offset_array, size / 2, kwal_file);
            			copy_cnt += size / 2;
            			goto next_cp_inode;
            		}
#endif
            		if((validity > FORCE_REMAP_VALIDITY) || ((validity > REMAP_VALIDITY)&&(ext_cnt>=MIN_REMAP))){
            			//do remap
#ifdef F2FS_REMAP
            			f2fs_remap_kwal(wrapfs_lower_inode(cl->inode), offset_array, size/2, kwal_file);
            			remap_cnt += size / 2;
#endif
#ifdef EXT4_EXT_REMAP
            			remap_extent_kwal(wrapfs_lower_inode(cl->inode),
            					offset_array, size / 2, kwal_file);
            			remap_cnt += size / 2;
#endif
            		} else {
            			//do copy
#ifdef COPY_CP
            			copy_kwal(cl->inode, offset_array, size / 2, kwal_file);
            			copy_cnt += size / 2;
#endif
            		}
#endif
            	}
            	next_cp_inode:
#endif

#ifndef SEL_REMAP
				if(size!=0){
#ifdef F2FS_REMAP
					f2fs_remap_kwal(wrapfs_lower_inode(cl->inode), offset_array, size/2, kwal_file);
#endif
#ifdef EXT4_EXT_REMAP
					remap_extent_kwal(wrapfs_lower_inode(cl->inode), offset_array, size/2, kwal_file);
					remap_cnt += size/2;
#endif
#ifdef COPY_CP
					copy_kwal(cl->inode, offset_array, size/2, kwal_file);
					copy_cnt += size/2;
#endif
				}
#endif

#ifdef F2FS_REMAP
				f2fs_remap_end(wrapfs_lower_inode(cl->inode));
#endif

#ifdef COPY_CP
				vfs_fsync(WRAPFS_I(cl->inode)->i_file,1);
#endif


				if(hash_empty(cl->redirection_hash)){
					hash_init(cl->redirection_hash);
					wi->commit_tree = NULL;
				}

				// make handle before calling remap_kwal()
				//			printk("offset_size %d\n", size);


				// log remapped information
				// log inode number, length = 0xFFFFFFFF

				kfree(offset_array);
				if(wi->commit_tree == NULL){
					list_del_init(&(cl->list));
					kfree(cl);
				}
				wrapfs_debug("unlock\n");
				up_write(&wi->redirection_tree_lock);
            }
            up_write(&kwal_i->commit_tree_lock);


			spin_lock(&remap_kwal_node->last_block_lock);
			remap_kwal_node->last_block = 0;
#ifndef NO_META
#ifndef SEQ_META
			remap_kwal_node->index_block =  (KWAL_SIZE/KiB(4))-1;
			curr_metablock = remap_kwal_node->index_block;
			remap_kwal_node->index_block--;
			remap_kwal_node->remained = remap_kwal_node->index_block- remap_kwal_node->last_block;
#else
			remap_kwal_node->index_block = remap_kwal_node->last_block++;
			curr_metablock = remap_kwal_node->index_block;
			remap_kwal_node->index_block = remap_kwal_node->last_block++;
			remap_kwal_node->remained = (KWAL_SIZE/KiB(4))-1;
#endif
#else
			remap_kwal_node->index_block =  (KWAL_SIZE/KiB(4))-1;
			remap_kwal_node->remained = (KWAL_SIZE/KiB(4))-1;
#endif
			spin_unlock(&remap_kwal_node->last_block_lock);

			//		wrapfs_debug("clear KWAL\n");

			trace_printk("[REMAP] %d %d\n", remap_cnt, copy_cnt);
			vfs_fsync(kwal_file, 0);

			trace_printk("truncate\n");

			do_truncate(file_dentry(kwal_file), 0, 0,NULL);

			trace_printk("logging\n");

			memset(buf, 0, PAGE_SIZE);
			mb_p = (char*)buf;

			mb = (__be32 *)mb_p;
			*mb = cpu_to_be32(KWAL_MAGIC);
			mb_p += sizeof(__be32);

			mb = (__be32 *)mb_p;
			*mb = cpu_to_be32(remap_kwal_node->num);
			mb_p += sizeof(__be32);

			//terminal char
			mb = (__be32 *)mb_p;
			*mb = cpu_to_be32(0xFFFFFFFF);
			mb_p += sizeof(__be32);
			mb = (__be32 *)mb_p;
			*mb = cpu_to_be32(0xFFFFFFFF);
			mb_p += sizeof(__be32);
#ifndef NO_META
			write_kwal_metadata(kwal_file, buf, curr_metablock);
#endif
			// add checkpoint log

			vfs_fsync(kwal_file, 0);

			trace_printk("fallocate\n");
			vfs_fallocate(kwal_file, 0, 0, KWAL_SIZE);

			trace_printk("[FF] %d\n", check_free_fragment(kwal_file->f_inode->i_sb));
			check_kwal_extents(kwal_file->f_path.dentry->d_inode);
#ifdef EXT4_EXT_REMAP
			frag=check_kwal_extents(kwal_file->f_path.dentry->d_inode);
#endif
#if 0
#ifdef SEL_REMAP
#define GTH MiB(10)
#define LTH MiB(15)
#define LOW_LOCAL (5)
#define HIGH_LOCAL (10)
			if(KWAL_SIZE/frag > GTH){
					do_copy = 0;
					trace_printk("nextR\n");
			}else{
					//        else if (KWAL_SIZE/frag < MiB(2)){
					do_copy = 1;
					trace_printk("nextC\n");
			}


			if((local_threshold>LOW_LOCAL)&&(KWAL_SIZE/frag >LTH)){
					local_threshold--;
			}else if(KWAL_SIZE/frag < LTH){
					local_threshold++;
					if(local_threshold > HIGH_LOCAL)
							local_threshold = HIGH_LOCAL;
			}
#endif
			trace_printk("local threshold %d\n", local_threshold);
#endif
			remap_kwal_node->on_remap=0;

			trace_printk("[LAT] end\n");
			up_write(&remap_kwal_node->on_io);
			wake_up(&kwal_i->remap_done);
			}

			for(i=0; i<KWAL_NUM; i++){
					if(kwal_i->kwals[i]->on_remap == 1){
							spin_lock(&kwal_i->curr_kwal_lock);
							kwal_i->to_remap_kwal = kwal_i->kwals[i];
							kwal_i->remap_trigger = 1;
							spin_unlock(&kwal_i->curr_kwal_lock);
							goto remap_loop;
					}
			}

			//sleep
			if (freezing(current)) {
					//        spin_unlock(&kwal_i->remap_lock);
					try_to_freeze();
					//        spin_lock(&kwal_i->remap_lock);
			} else {
					DEFINE_WAIT(wait);

					prepare_to_wait(&kwal_i->remap_done, &wait,
									TASK_INTERRUPTIBLE);
					//        spin_unlock(&kwal_i->remap_lock);
					schedule();
					//        spin_lock(&kwal_i->remap_lock);
					finish_wait(&kwal_i->remap_done, &wait);
			}
			goto remap_loop;

}

int kwal_init(struct super_block *sb){
		struct wrapfs_sb_info* sbi = WRAPFS_SB(sb);
		struct kwal_info *kwal_i;
		struct file* kwal_file;
		char *buf;
		char name[100];
		char *mb_p;
		__be32 *mb;
		int err;
		int i;
		struct task_struct *t;

		if(sbi == NULL){
				printk("sbi == null\n");
				return -1;
		}

		kwal_i = &(sbi->kwal_info);

		buf = (char *)kmalloc(PAGE_SIZE, GFP_KERNEL);

		kwal_i->remap_trigger = -1;

		if(kwal_i->kwals[0] != NULL)
				return -1;

		mutex_init(&kwal_i->atomic_mutex);
#if (KWAL_NUM <= 2)
		init_rwsem(&kwal_i->big_kwal_mutex);
#endif
		init_rwsem(&kwal_i->commit_tree_lock);
		spin_lock_init(&kwal_i->remap_lock);
		spin_lock_init(&kwal_i->curr_kwal_lock);
		spin_lock_init(&kwal_i->curr_index_lock);
		INIT_LIST_HEAD(&kwal_i->per_inode_commit_tree);


		//    kwal_i->kwal_indexes[0] = (struct kwal_node *)kmalloc(sizeof(struct kwal_node), GFP_KERNEL);
		//    kwal_i->kwal_indexes[1] = (struct kwal_node *)kmalloc(sizeof(struct kwal_node), GFP_KERNEL);
		//    memset(kwal_i->kwal_indexes[0] , 0, sizeof(struct kwal_node));
		//    memset(kwal_i->kwal_indexes[1] , 0, sizeof(struct kwal_node));

		//    memset(name, 0, sizeof(name));
		//    sprintf(name, "kwal_indexA");
		//    printk("%s kwal file\n", name);
		//    kwal_i->kwal_indexes[0]->kwal_file = (void*)wrapfs_lower_file((filp_open(name, O_RDWR|O_CREAT, 0644)));
		//
		//    memset(name, 0, sizeof(name));
		//    sprintf(name, "kwal_indexB");
		//    printk("%s kwal file\n", name);
		//    kwal_i->kwal_indexes[1]->kwal_file = (void*)wrapfs_lower_file((filp_open(name, O_RDWR|O_CREAT, 0644)));
		//
		//
		//    kwal_i->kwal_indexes[0]->last_block = 0;
		//    spin_lock_init(&kwal_i->kwal_indexes[0]->last_block_lock);
		//    init_rwsem(&kwal_i->kwal_indexes[0]->on_io);
		//
		//    kwal_i->kwal_indexes[1]->last_block = 0;
		//    spin_lock_init(&kwal_i->kwal_indexes[1]->last_block_lock);
		//    init_rwsem(&kwal_i->kwal_indexes[1]->on_io);


		//setting current kwal_index
		//    kwal_i->kwal_index = kwal_i->kwal_indexes[0];

		//    kwal_file = (struct file*) (kwal_i->kwal_index->kwal_file);
		//    kwal_inode = file_inode(kwal_file);
		//
		//    memset(buf, 0, 32);
		//    mb_p = (char*)buf;
		//
		//    mb = (__be32 *)mb_p;
		//    *mb = cpu_to_be32(KWAL_MAGIC);
		//    mb_p += sizeof(__be32);
		//
		//    //terminal char
		//    mb = (__be32 *)mb_p;
		//    *mb = cpu_to_be32(0xFFFFFFFF);
		//    mb_p += sizeof(__be32);
		//    mb = (__be32 *)mb_p;
		//    *mb = cpu_to_be32(0xFFFFFFFF);
		//    mb_p += sizeof(__be32);
		//
		//    write_kwal_metadata(kwal_file, buf, kwal_i->kwal_index->last_block);
		//    kwal_i->kwal_index->last_block++;
		////add fallocation
		//    vfs_fallocate(kwal_i->kwal_indexes[0]->kwal_file, 0, 0, KWAL_SIZE);
		//    vfs_fallocate(kwal_i->kwal_indexes[1]->kwal_file, 0, 0, KWAL_SIZE);
		//
		//    vfs_fsync(kwal_i->kwal_indexes[0]->kwal_file, 0);
		//    vfs_fsync(kwal_i->kwal_indexes[1]->kwal_file, 0);

		//kwal index setting end

		for(i=0; i<KWAL_NUM; i++){
				memset(name, 0, sizeof(name));
				//        strncpy(name,sb->s_root->d_name.name, sb->s_root->d_name.len);
				sprintf(name, "kwal_%d", i);

				printk("%s kwal file\n", name);

				kwal_file = wrapfs_lower_file((filp_open(name, O_RDWR|O_CREAT, 0644)));
				//       	ext4_set_nonda(kwal_inode);


				kwal_i->kwals[i] = (struct kwal_node *)kmalloc(sizeof(struct kwal_node), GFP_KERNEL);
				memset(kwal_i->kwals[i], 0, sizeof(struct kwal_node));

				kwal_i->kwals[i]->kwal_file = (void*)kwal_file;
				kwal_i->kwals[i]->last_block = 0;
				kwal_i->kwals[i]->num = i;
				kwal_i->kwals[i]->on_remap = 0;
				kwal_i->kwals[i]->remap_ready = 0;
#ifndef NO_META
#ifndef SEQ_META
				kwal_i->kwals[i]->index_block = (KWAL_SIZE/KiB(4))-1;
#else
				kwal_i->kwals[i]->index_block = kwal_i->kwals[i]->last_block++;
#endif
#else
				kwal_i->kwals[i]->index_block = (KWAL_SIZE/KiB(4))-1;
#endif
				init_rwsem(&kwal_i->kwals[i]->cp_mutex);
				spin_lock_init(&kwal_i->kwals[i]->last_block_lock);
				init_rwsem(&kwal_i->kwals[i]->on_io);
				atomic_set(&kwal_i->kwals[i]->inflight_txs, 0);

				vfs_fallocate(kwal_file, 0, 0, KWAL_SIZE);

				vfs_fsync(kwal_file, 0);
		}

		for(i=0; i<KWAL_NUM; i++){

			// init metadata
			kwal_file = (struct file*) (kwal_i->kwals[i]->kwal_file);

			memset(buf, 0, 32);
			mb_p = (char*)buf;

			mb = (__be32 *)mb_p;
			*mb = cpu_to_be32(KWAL_MAGIC);
			mb_p += sizeof(__be32);

			mb = (__be32 *)mb_p;
			*mb = cpu_to_be32(i);
			mb_p += sizeof(__be32);

			//terminal char
			mb = (__be32 *)mb_p;
			*mb = cpu_to_be32(0xFFFFFFFF);
			mb_p += sizeof(__be32);
			mb = (__be32 *)mb_p;
			*mb = cpu_to_be32(0xFFFFFFFF);
			mb_p += sizeof(__be32);

	#ifndef NO_META
			write_kwal_metadata(kwal_file, buf, kwal_i->kwals[i]->index_block);
	#ifndef SEQ_META
			kwal_i->kwals[i]->index_block--;
	#else
			kwal_i->kwals[i]->index_block = kwal_i->kwals[i]->last_block++;
	#endif
	#endif
			kwal_i->kwals[i]->remained = kwal_i->kwals[i]->index_block - kwal_i->kwals[i]->last_block;
		}
		kwal_i->curr_kwal = kwal_i->kwals[0];

		init_waitqueue_head(&kwal_i->remap_done);

		kfree(buf);

		t = kthread_run(remapd, kwal_i, "remapd");
		if (IS_ERR(t))
				return PTR_ERR(t);
		wait_event(kwal_i->remap_done, kwal_i->remap_trigger == 0);

		return 0;
}


asmlinkage long sys_tx_start(unsigned int target_fd)
{
		long result = 0;
		struct file *target_file;
		struct wrapfs_file_info * wf_target;
		struct wrapfs_inode_info *wi_target;
		struct inode *target_inode;
		struct kwal_info *kwal_i;
		struct redirection_entry *entry, *tentry;
		int err;
		int now;

		wrapfs_debug("start\n");

		target_file = fget(target_fd);
		wf_target = WRAPFS_F(target_file);

		wi_target = WRAPFS_I(file_inode(target_file));
		target_inode = file_inode(target_file);
		kwal_i = &(WRAPFS_SB(target_inode->i_sb)->kwal_info);


		down_write(&wi_target->redirection_tree_lock);
		now = wi_target->time++;

		wi_target->active_txs++;

		if(wi_target->commit_tree == NULL)
			init_commit_tree(kwal_i, wi_target);

		up_write(&wi_target->redirection_tree_lock);

		down_write(&wf_target->redirection_tree_lock);

		wf_target->read_cache_blk = -1;
		wf_target->read_cache_time = -1;
		wf_target->is_tx = 1;
		wf_target->is_abort = 0;
		wf_target->start_time = now;
		up_write(&wf_target->redirection_tree_lock);

		fput(target_file);
		wrapfs_debug("end\n");
		return result;
}
asmlinkage long sys_tx_abort(unsigned int target_fd)
{
		struct file *target_file, *kwal_file;
		struct inode *target_inode;

		struct wrapfs_file_info * wf_target;
		struct wrapfs_inode_info *wi_target;

		struct kwal_info *kwal_i;
		struct redirection_entry *entry, *tentry;
		struct page *page;
		int i;

		//    wrapfs_debug("start\n");

		target_file = fget(target_fd);
		wf_target = WRAPFS_F(target_file);
		target_inode = file_inode(target_file);
		wi_target = WRAPFS_I(target_inode);
		kwal_i = &(WRAPFS_SB(target_inode->i_sb)->kwal_info);


		spin_lock(&kwal_i->curr_kwal_lock);
		kwal_file = kwal_i->curr_kwal->kwal_file;
		spin_unlock(&kwal_i->curr_kwal_lock);

		// remove temp tree
		down_write(&wf_target->redirection_tree_lock);

		hash_for_each_safe(wf_target->redirection_hash,i,tentry,entry,node){
				hash_del(&entry->node);

				page = find_get_page(kwal_file->f_mapping, get_kwal_blk(entry->new_block));
				kwal_file->f_mapping->a_ops->invalidatepage(page, 0 ,PAGE_SIZE);

				kfree(entry);
		}

		hash_init(wf_target->redirection_hash);
		wf_target->is_tx = 0;
		up_write(&wf_target->redirection_tree_lock);

		fput(target_file);
		//	wrapfs_debug("end\n");
		return 0;
}

asmlinkage long sys_tx_end(unsigned int target_fd)
{
		struct file *target_file;
		struct wrapfs_file_info * wf_target;
		struct wrapfs_inode_info *wi_target;
		struct inode *target_inode;
		struct kwal_info *kwal_i;
		struct commit_tree_list *target_ct;
		unsigned long _last_block[KWAL_NUM];
		struct redirection_entry *entry, *tentry;
		int i;
		int abort;
		int now;
			wrapfs_debug("start\n");

		target_file = fget(target_fd);
		wf_target = WRAPFS_F(target_file);
		target_inode = file_inode(target_file);
		wi_target = WRAPFS_I(target_inode);

		kwal_i = &(WRAPFS_SB(target_inode->i_sb)->kwal_info);

		down_write(&wi_target->redirection_tree_lock);
		target_ct = init_commit_tree(kwal_i, wi_target);

		//#endif
		for(i=0; i<KWAL_NUM; i++)
				_last_block[i]=0;

		now = wi_target->time++;
		//    wrapfs_debug("%d\n", now);
		wi_target->active_txs--;
		// migrate temp tree to commit tree
		abort = wf_target->is_abort;
		if(abort)
			trace_printk("CONFLICT!!\n");
		down_write(&wf_target->redirection_tree_lock);

		list_for_each_entry_safe(entry, tentry, &wf_target->traversing_listhead, next_entry){
				hash_del(&entry->node);
				list_del(&entry->next_entry);
#ifdef FINEWC_DETECT
				if(entry->is_conflict == 1){
					struct conflict_entry *c_entry, *found_c_entry=NULL;
					struct redirection_entry* valid_block;

					hash_for_each_possible(target_ct->conflict_hash,c_entry,conflict_node,entry->org_block){
						if(c_entry->org_block == entry->org_block){
							found_c_entry=c_entry;
						}
					}

					wrapfs_debug("[%d] %lu->%lu conflict\n", wi_target->lower_inode->i_ino, entry->org_block, entry->new_block);
					// if is_conflict is set, do merge
					// go merge
					valid_block = blk_redirection_closed_txs(target_ct, entry->org_block, INT_MAX);
					if(valid_block != NULL && abort==0)
						entry->cs = write_from_dirtybitmap(kwal_i->kwals[get_kwal_num(valid_block->new_block)]->kwal_file,
								get_kwal_blk(valid_block->new_block), get_kwal_blk(entry->new_block), entry->p_staging->dirtybitmap);

					if(found_c_entry!=NULL){
						wrapfs_debug("0x%016llX:0x%016llX\n",found_c_entry->dirtybitmap,entry->p_staging->dirtybitmap);
						found_c_entry->dirtybitmap &= ~entry->p_staging->dirtybitmap;
						wrapfs_debug("0x%016llX\n",found_c_entry->dirtybitmap);
						if(found_c_entry->dirtybitmap == 0ULL){
							//do delete conflict node
							wrapfs_debug("delete conflict node[%d] %lu->%lu\n", wi_target->lower_inode->i_ino, entry->org_block, entry->new_block);
							hash_del(&found_c_entry->conflict_node);
							kfree(found_c_entry);
						}
					}
				}
#endif
				if(abort==0){
					target_ct->remap_length +=
							add_redirection_entry_closed_txs(target_ct, entry->org_block, entry->new_block, entry->cs, now);
					target_ct->written_length++;
				}

				if(_last_block[get_kwal_num(entry->new_block)] < get_kwal_blk(entry->new_block))
						_last_block[get_kwal_num(entry->new_block)] = get_kwal_blk(entry->new_block);
#ifdef FINEWC_DETECT
				if(entry->p_staging != NULL){
					wrapfs_debug("staging node delete [%d] %lu->%lu\n", wi_target->lower_inode->i_ino, entry->org_block, entry->new_block);
					hash_del(&entry->p_staging->staging_node);
					kfree(entry->p_staging);
				}
#endif
				kfree(entry);
		}
		list_del_init(&wf_target->traversing_listhead);
		hash_init(wf_target->redirection_hash);
		wf_target->is_tx = 0;
#ifdef RR_ISO
		if(wi_target->active_txs == 0){
				// resetting time
				//		wrapfs_debug("[%lu] reset time\n", target_ct->ino);
				wi_target->time=0;
				list_for_each_entry_safe(entry, tentry, &target_ct->active_entry_head, next_active){
						entry->endt = -1;
						INIT_LIST_HEAD(&entry->next_version);
						list_del_init(&entry->next_active);
				}
				INIT_LIST_HEAD(&target_ct->active_entry_head);
				//		wrapfs_debug("do gc\n");
				// do GC redundant redirection entry
				list_for_each_entry_safe(entry, tentry, &target_ct->gc_list, gc_entry){
						wrapfs_debug("GC [%lu] %lu->%lu\n", target_ct->ino, get_kwal_blk(entry->org_block), get_kwal_blk(entry->new_block));
						list_del_init(&entry->gc_entry);
						list_del_init(&entry->next_version);
						kfree(entry);
				}
		}
#endif
		for(i=0; i<KWAL_NUM; i++){
				if(wf_target->written_kwals[i] == 1){
						if(atomic_dec_and_test(&kwal_i->kwals[i]->inflight_txs))
								wake_up_atomic_t(&kwal_i->kwals[i]->inflight_txs);
						wf_target->written_kwals[i] = 0;
				}
		}

		up_write(&wf_target->redirection_tree_lock);
		up_write(&wi_target->redirection_tree_lock);
		for(i=0; i<KWAL_NUM; i++)
				if(_last_block[i] > kwal_i->kwals[i]->last_block){
						printk("%lu[%d] > %llu[%d]\n",_last_block[i],i, kwal_i->kwals[i]->last_block,i);
						BUG();
				}

		fput(target_file);
		//	wrapfs_debug("mutex try unlock [%s]\n", file_dentry(target_file)->d_name.name);
		//	mutex_unlock(&wi_target->atomic_mutex);
//			wrapfs_debug("end\n");

		return abort;
}
#ifdef KWAL_BUG
int counter_bug=0;
#endif

//#define MAX_KWAL_SIZE (4096*1UL)
//#define MAX_KWAL_SIZE (4096*1UL)
asmlinkage long sys_tx_commit(unsigned int *target_fd_array, int len){
		struct file *target_file, *kwal_file;
		struct wrapfs_file_info * wf_target;
		struct wrapfs_inode_info *wi_target;
		struct inode *target_inode;
		struct kwal_info *kwal_i;
		char *buf;
		char *mb_p;
		__be32 *mb;
		__be64 *mb2;
		struct commit_tree_list *cl;
		int length=0;
		int min_block=INT_MAX;
		int max_block=0;
		long long remap_trigger;
		struct kwal_node *commit_kwal_node;
		struct redirection_entry *entry, *tentry;
		int i;
		unsigned long offset;
		int retry=0;
		int remap = 0;
		unsigned long long curr_metablock;
		int write_length=0;
		struct timeval start,end,ret;
		//    int curr_base, curr_kwal_num, commit_kwal_num;

		//this is trick
		//getting sb from one fd
		//because all fd have same sb
		    wrapfs_debug("start\n");

		    do_gettimeofday(&start);

		target_file = fget(target_fd_array[0]);
		target_inode = file_inode(target_file);
		wf_target = WRAPFS_F(target_file);
		wi_target = WRAPFS_I(target_inode);
		kwal_i = &(WRAPFS_SB(target_inode->i_sb)->kwal_info);

		//	printk("sys_tx_commit\n");

		spin_lock(&kwal_i->curr_kwal_lock);
#ifdef KWAL_BUG
		if(counter_bug++ > 100){
			do_kwal_crash(kwal_i);
			BUG();
		}
#endif
		commit_kwal_node = kwal_i->curr_kwal;

#ifndef SEQ_META
		commit_kwal_node->remained = commit_kwal_node->index_block - commit_kwal_node->last_block;
#else
		commit_kwal_node->remained = (KWAL_SIZE/KiB(4))-commit_kwal_node->last_block;
#endif

		remap_trigger = (commit_kwal_node->remained * KiB(4) - (GUARD_SIZE));
		if(remap_trigger < 0){
				int using_kwal = (kwal_i->curr_kwal->num + KWAL_NUM-1)%KWAL_NUM;
				remap = 1;
				kwal_i->curr_kwal = kwal_i->kwals[(kwal_i->curr_kwal->num+1)%KWAL_NUM];

				while(kwal_i->curr_kwal->on_remap == 1){
						if(using_kwal == kwal_i->curr_kwal->num)
								break;
						kwal_i->curr_kwal = kwal_i->kwals[(kwal_i->curr_kwal->num+1)%KWAL_NUM];
				}

				while(kwal_i->curr_kwal->on_remap == 1){
						wrapfs_debug("wait_remap\n");
						spin_unlock(&kwal_i->curr_kwal_lock);
						wait_event(kwal_i->remap_done, kwal_i->curr_kwal->on_remap == 0); // KWAL_NUM <2
						spin_lock(&kwal_i->curr_kwal_lock);
						wrapfs_debug("finish remap %d\n", commit_kwal_node->num);
				}
		}
		spin_unlock(&kwal_i->curr_kwal_lock);

		wrapfs_debug("wait s %d\n", atomic_read(&commit_kwal_node->inflight_txs));
		wait_on_atomic_t(&commit_kwal_node->inflight_txs,
						kwal_wait_tx_end_atomic_t,
						TASK_UNINTERRUPTIBLE);
		wrapfs_debug("wait e\n");

		down_read(&kwal_i->commit_tree_lock);
		list_for_each_entry(cl, &kwal_i->per_inode_commit_tree, list){
				length += cl->length;
		}
		up_read(&kwal_i->commit_tree_lock);

		if(0 == length){
				wrapfs_debug("fast end\n");
				goto out_commit;
		}
		//	wrapfs_debug("start\n");
		kwal_file = (struct file *)(commit_kwal_node->kwal_file);

		//    wrapfs_debug("end\n");
		//    vfs_fsync(kwal_file,1); // fsync kwal data file

#ifndef NO_META
		spin_lock(&commit_kwal_node->last_block_lock);
		curr_metablock = commit_kwal_node->index_block;
#ifndef SEQ_META
		commit_kwal_node->index_block--;
		commit_kwal_node->remained = commit_kwal_node->index_block - commit_kwal_node->last_block;
		if(commit_kwal_node->remained < 1){
				if(commit_kwal_node->last_block < (KWAL_SIZE)/KiB(4)){
						commit_kwal_node->last_block = KWAL_SIZE/KiB(4)+1;
						//    		wrapfs_debug("resetting lastblock A\n");
				}
				curr_metablock = commit_kwal_node->last_block;
				//    	wrapfs_debug("overflow metaA [%llu]\n", curr_metablock);
				commit_kwal_node->last_block++;
				commit_kwal_node->index_block++;
				WARN_ON_ONCE(1);
		}
#else
		commit_kwal_node->index_block = commit_kwal_node->last_block++;
#endif
		spin_unlock(&commit_kwal_node->last_block_lock);
#endif

		buf = (char *)kmalloc(PAGE_SIZE, GFP_KERNEL);
		memset(buf, 0, PAGE_SIZE);
		mb_p = (char*)buf;
		offset = 0;


		wrapfs_debug("loop start\n");
		down_read(&kwal_i->commit_tree_lock);

		// for each commit list
		list_for_each_entry(cl, &kwal_i->per_inode_commit_tree, list){
				struct wrapfs_inode_info *wi = WRAPFS_I(cl->inode);

				if(0 == cl->length)
						continue;
				wrapfs_debug("ino [%lu]\n", cl->ino);
				//		wrapfs_debug("log start\n");

				// size of remap entries for an inode exceeds PAGE_SIZE
				if(PAGE_SIZE < ((cl->length+1) * 2 * sizeof(__be32))){
						// do special thing
						// seperating commit tree with same inode number
						//			wrapfs_debug("do special thing [%s]\n",file_dentry(target_file)->d_name.name);
				}

				// metablock is full with redirection entry
				if(PAGE_SIZE < (offset + (5 * sizeof(__be32)))){
						//we shoud go next block

						if(offset > PAGE_SIZE)
								BUG();

						//			wrapfs_debug("metablock is full A part\n");
						//erase 0 enrty
						mb_p -= sizeof(__be32);
						offset -= sizeof(__be32);
#ifndef NO_META
						write_kwal_metadata(kwal_file, buf, curr_metablock);
						write_length++;

						spin_lock(&commit_kwal_node->last_block_lock);
						curr_metablock = commit_kwal_node->index_block;
#ifndef SEQ_META
						commit_kwal_node->index_block--;
						commit_kwal_node->remained = commit_kwal_node->index_block - commit_kwal_node->last_block;
						if(commit_kwal_node->remained < 1){
								if(commit_kwal_node->last_block < ((KWAL_SIZE)/KiB(4))){
										commit_kwal_node->last_block = KWAL_SIZE/KiB(4)+1;
										//            		wrapfs_debug("resetting lastblock B\n");
								}
								curr_metablock = commit_kwal_node->last_block;
								//            	wrapfs_debug("overflow metaB [%llu]\n", curr_metablock);
								commit_kwal_node->last_block++;
								commit_kwal_node->index_block++;
								WARN_ON_ONCE(1);
						}
#else
						commit_kwal_node->index_block = commit_kwal_node->last_block++;
#endif
						spin_unlock(&commit_kwal_node->last_block_lock);
#endif

						offset = 0;

						memset(buf, 0, PAGE_SIZE);
						mb_p = (char*)buf;


				}

				down_write(&wi->redirection_tree_lock);
				mb = (__be32 *)mb_p;
				*mb = cpu_to_be32(cl->inode->i_ino);
				mb_p += sizeof(__be32);
				offset += sizeof(__be32);

				mb = (__be32 *)mb_p;
				*mb = cpu_to_be32(cl->length);
				mb_p += sizeof(__be32);
				offset += sizeof(__be32);


				//		wrapfs_debug("[%lu]\n", cl->inode->i_ino);
				wrapfs_debug("ino %u(%d)\n", cl->inode->i_ino,cl->length);


				//		wrapfs_debug("each_entry\n");
				list_for_each_entry_safe(entry, tentry, &cl->dirty_listhead, next_entry){
						if(entry->dirt == 0){
								BUG();
						}
						//            wrapfs_debug("[log] %lu -> %lu\n", entry->org_block, entry->new_block);

						entry->dirt = 0;

						mb = (__be32 *)mb_p;
						*mb = cpu_to_be32(entry->org_block);
						mb_p += sizeof(__be32);
						offset += sizeof(__be32);

						mb = (__be32 *)mb_p;
						*mb = cpu_to_be32(entry->new_block);
						mb_p += sizeof(__be32);
						offset += sizeof(__be32);

						mb = (__be32 *)mb_p;
						*mb = cpu_to_be32(entry->cs);
						mb_p += sizeof(__be32);
						offset += sizeof(__be32);
						write_length++;

						wrapfs_debug("%u:%u[%08X]\n", entry->org_block, get_kwal_blk(entry->new_block), entry->cs);
						//count++;
						if(entry->new_block < min_block)
								min_block = entry->new_block;
						if(entry->new_block > max_block)
								max_block = entry->new_block;

						if((offset + (sizeof(__be32)*5)) > PAGE_SIZE){
								//              wrapfs_debug("metablock is full B part\n");
								if(offset > PAGE_SIZE)
										BUG();
#ifndef NO_META
								write_kwal_metadata(kwal_file, buf, curr_metablock);
								write_length++;

								spin_lock(&commit_kwal_node->last_block_lock);
								curr_metablock = commit_kwal_node->index_block;
#ifndef SEQ_META
								commit_kwal_node->index_block--;
								commit_kwal_node->remained = commit_kwal_node->index_block - commit_kwal_node->last_block;
								if(commit_kwal_node->remained < 1){
										if(commit_kwal_node->last_block < KWAL_SIZE/KiB(4)){
												commit_kwal_node->last_block = KWAL_SIZE/KiB(4)+1;
												//                		wrapfs_debug("resetting lastblock C\n");
										}
										curr_metablock = commit_kwal_node->last_block;
										//                	wrapfs_debug("overflow metaC [%llu]\n", curr_metablock);
										commit_kwal_node->last_block++;
										commit_kwal_node->index_block++;
										WARN_ON_ONCE(1);
								}
#else
								commit_kwal_node->index_block = commit_kwal_node->last_block++;
#endif
								spin_unlock(&commit_kwal_node->last_block_lock);
#endif
								offset = 0;
								memset(buf, 0, PAGE_SIZE);
								mb_p = (char*)buf;
						}
						list_del_init(&entry->next_entry);
						//            wrapfs_debug("next\n");
				}
				if(i_size_read(&wi->vfs_inode) <= wi->kwal_isize){
						i_size_write(wi->lower_inode,wi->kwal_isize);
						i_size_write(&wi->vfs_inode,wi->kwal_isize);
				}
				cl->length = 0;
				up_write(&wi->redirection_tree_lock);

				mb2 = (__be64 *)mb_p;
				*mb2 = cpu_to_be64(wi->kwal_isize);
				mb_p += sizeof(__be64);
				offset += sizeof(__be64);

				wrapfs_debug("%llu\n", wi->kwal_isize);
				// if metablock is not full
				mb = (__be32 *)mb_p;
				*mb = cpu_to_be32(0x0);
				mb_p += sizeof(__be32);
				offset += sizeof(__be32);

				//		wrapfs_debug("log end\n");
		}
		up_read(&kwal_i->commit_tree_lock);

		//	wrapfs_debug("loop end\n");
		//    wrapfs_debug("f1 s\n");
		//	vfs_fsync(kwal_file, 1);
		//    wrapfs_debug("f1 e\n");
		//wrapfs_debug("commit %d\n", count);
		//terminal char

		//erase 0 enrty

		//TODO: should be correct
//		mb_p -= sizeof(__be32);

		mb = (__be32 *)mb_p;
		*mb = cpu_to_be32(0xFFFFFFFF);
		mb_p += sizeof(__be32);
#ifndef NO_META
		write_kwal_metadata(kwal_file, buf, curr_metablock);
		write_length++;
#endif
		//    vfs_fsync(kwal_file, 1);


		//    wrapfs_debug("write end\n");

		//    ext4_sync_file(kwal_file,0,LONG_MAX,1);


		vfs_fsync(kwal_file, 1);

		//    ext4_sync_file(kwal_file, 0, LONG_MAX, 1);

		kfree(buf);
		//	wrapfs_debug("mtx s\n");

		//    wrapfs_debug("end\n");
out_commit:

		if(remap == 1){
				//       wrapfs_debug("remap %d\n", commit_kwal_node->num);

				spin_lock(&kwal_i->curr_kwal_lock);
				kwal_i->remap_trigger = 1;
				kwal_i->to_remap_kwal = commit_kwal_node;
				commit_kwal_node->on_remap = 1;
				spin_unlock(&kwal_i->curr_kwal_lock);
				wake_up(&kwal_i->remap_done);

		};
#ifdef COMMIT_LAT
		do_gettimeofday(&end);
		calc_time(start, end, &ret);
		if(write_length != 0)
			trace_printk("%ld.%06ld %d\n", ret.tv_sec, ret.tv_usec, write_length*4);
#endif
		fput(target_file);
		//    wrapfs_debug("end\n");
		return 0;
}

static ssize_t wrapfs_read(struct file *file, char __user *buf,
				size_t count, loff_t *ppos)
{
		int err;
		struct file *lower_file;
		struct dentry *dentry = file->f_path.dentry;

		lower_file = wrapfs_lower_file(file);
		err = vfs_read(lower_file, buf, count, ppos);
		/* update our inode atime upon a successful lower read */
		if (err >= 0)
				fsstack_copy_attr_atime(d_inode(dentry),
								file_inode(lower_file));

		return err;
}

static ssize_t wrapfs_write(struct file *file, const char __user *buf,
				size_t count, loff_t *ppos)
{
		int err;

		struct file *lower_file;
		struct dentry *dentry = file->f_path.dentry;

		lower_file = wrapfs_lower_file(file);
		err = vfs_write(lower_file, buf, count, ppos);
		/* update our inode times+sizes upon a successful lower write */
		if (err >= 0) {
				fsstack_copy_inode_size(d_inode(dentry),
								file_inode(lower_file));
				fsstack_copy_attr_times(d_inode(dentry),
								file_inode(lower_file));
		}

		return err;
}

static int wrapfs_readdir(struct file *file, struct dir_context *ctx)
{
		int err;
		struct file *lower_file = NULL;
		struct dentry *dentry = file->f_path.dentry;

		lower_file = wrapfs_lower_file(file);
		err = iterate_dir(lower_file, ctx);
		file->f_pos = lower_file->f_pos;
		if (err >= 0)		/* copy the atime */
				fsstack_copy_attr_atime(d_inode(dentry),
								file_inode(lower_file));
		return err;
}

static long wrapfs_unlocked_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
		long err = -ENOTTY;
		struct file *lower_file;

		lower_file = wrapfs_lower_file(file);

		/* XXX: use vfs_ioctl if/when VFS exports it */
		if (!lower_file || !lower_file->f_op)
				goto out;
		if (lower_file->f_op->unlocked_ioctl)
				err = lower_file->f_op->unlocked_ioctl(lower_file, cmd, arg);

		/* some ioctls can change inode attributes (EXT2_IOC_SETFLAGS) */
		if (!err)
				fsstack_copy_attr_all(file_inode(file),
								file_inode(lower_file));
out:
		return err;
}

#ifdef CONFIG_COMPAT
static long wrapfs_compat_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
		long err = -ENOTTY;
		struct file *lower_file;

		lower_file = wrapfs_lower_file(file);

		/* XXX: use vfs_ioctl if/when VFS exports it */
		if (!lower_file || !lower_file->f_op)
				goto out;
		if (lower_file->f_op->compat_ioctl)
				err = lower_file->f_op->compat_ioctl(lower_file, cmd, arg);

out:
		return err;
}
#endif

static int wrapfs_mmap(struct file *file, struct vm_area_struct *vma)
{
		int err = 0;
		bool willwrite;
		struct file *lower_file;
		const struct vm_operations_struct *saved_vm_ops = NULL;

		/* this might be deferred to mmap's writepage */
		willwrite = ((vma->vm_flags | VM_SHARED | VM_WRITE) == vma->vm_flags);

		/*
		 * File systems which do not implement ->writepage may use
		 * generic_file_readonly_mmap as their ->mmap op.  If you call
		 * generic_file_readonly_mmap with VM_WRITE, you'd get an -EINVAL.
		 * But we cannot call the lower ->mmap op, so we can't tell that
		 * writeable mappings won't work.  Therefore, our only choice is to
		 * check if the lower file system supports the ->writepage, and if
		 * not, return EINVAL (the same error that
		 * generic_file_readonly_mmap returns in that case).
		 */
		lower_file = wrapfs_lower_file(file);
		if (willwrite && !lower_file->f_mapping->a_ops->writepage) {
				err = -EINVAL;
				printk(KERN_ERR "wrapfs: lower file system does not "
								"support writeable mmap\n");
				goto out;
		}

		/*
		 * find and save lower vm_ops.
		 *
		 * XXX: the VFS should have a cleaner way of finding the lower vm_ops
		 */
		if (!WRAPFS_F(file)->lower_vm_ops) {
				err = lower_file->f_op->mmap(lower_file, vma);
				if (err) {
						printk(KERN_ERR "wrapfs: lower mmap failed %d\n", err);
						goto out;
				}
				saved_vm_ops = vma->vm_ops; /* save: came from lower ->mmap */
		}

		/*
		 * Next 3 lines are all I need from generic_file_mmap.  I definitely
		 * don't want its test for ->readpage which returns -ENOEXEC.
		 */
		file_accessed(file);
		vma->vm_ops = &wrapfs_vm_ops;

		file->f_mapping->a_ops = &wrapfs_aops; /* set our aops */
		if (!WRAPFS_F(file)->lower_vm_ops) /* save for our ->fault */
				WRAPFS_F(file)->lower_vm_ops = saved_vm_ops;

out:
		return err;
}

static int wrapfs_open(struct inode *inode, struct file *file)
{
		int err = 0;
		struct file *lower_file = NULL;
		struct path lower_path;
		struct wrapfs_file_info *wf;
		struct wrapfs_inode_info *wi = WRAPFS_I(inode);
		/* don't open unhashed/deleted files */
		if (d_unhashed(file->f_path.dentry)) {
				err = -ENOENT;
				goto out_err;
		}

		file->private_data =
				kzalloc(sizeof(struct wrapfs_file_info), GFP_KERNEL);
		if (!WRAPFS_F(file)) {
				err = -ENOMEM;
				goto out_err;
		}
		wf = WRAPFS_F(file);
		/* open lower object and link wrapfs's file struct to lower's */
		wrapfs_get_lower_path(file->f_path.dentry, &lower_path);
		lower_file = dentry_open(&lower_path, file->f_flags, current_cred());
		path_put(&lower_path);
		if (IS_ERR(lower_file)) {
				err = PTR_ERR(lower_file);
				lower_file = wrapfs_lower_file(file);
				if (lower_file) {
						wrapfs_set_lower_file(file, NULL);
						fput(lower_file); /* fput calls dput for lower_dentry */
				}
		} else {
				int i;
				//	init tx info
				//        wrapfs_debug("open [%s]\n", file_dentry(file)->d_name.name);
				hash_init(wf->redirection_hash);
				init_rwsem(&wf->redirection_tree_lock);
				INIT_LIST_HEAD(&wf->traversing_listhead);
				wf->redir_len=0;
				wf->is_tx=0;
				wf->is_abort=0;
#ifdef COPY_CP
				WRAPFS_I(inode)->i_file = lower_file;
#endif
				for(i=0;i<KWAL_NUM;i++)
						wf->written_kwals[i] = 0;
				wrapfs_set_lower_file(file, lower_file);
				//		wrapfs_debug("%lu size\n",i_size_read(wrapfs_lower_inode(inode)));
		}

		if (err)
				kfree(WRAPFS_F(file));
		else
				fsstack_copy_attr_all(inode, wrapfs_lower_inode(inode));

		if(wi->commit_tree != NULL){
				//		wrapfs_debug("reopen\n");
				i_size_write(inode, wi->kwal_isize);
		}
out_err:
		return err;
}

static int wrapfs_flush(struct file *file, fl_owner_t id)
{
		int err = 0;
		struct file *lower_file = NULL;
		struct inode *inode = file->f_path.dentry->d_inode;
		struct commit_tree_list * target_ct;
		struct wrapfs_inode_info * wi_target;
		struct wrapfs_file_info *wf;
		struct kwal_info * kwal_i;
		struct file * kwal_file;
		unsigned long* offset_array;
		struct redirection_entry *entry, *tentry;
		int size;
		int i;
		int now;

		lower_file = wrapfs_lower_file(file);

		wi_target = WRAPFS_I(inode);
		wf = WRAPFS_F(file);

		if(mutex_is_locked(&wi_target->atomic_mutex))
				mutex_unlock(&wi_target->atomic_mutex);

		//    wrapfs_debug("[%lu]: [%s]\n",inode->i_ino, file_dentry(file)->d_name.name);

		down_read(&wf->redirection_tree_lock);
		if(hash_empty(wf->redirection_hash)){
				//        wrapfs_debug("[%lu]: no t-tree\n", inode->i_ino);
				up_read(&wf->redirection_tree_lock);

				goto no_tx;
		}
		up_read(&wf->redirection_tree_lock);

		kwal_i = &(WRAPFS_SB(inode->i_sb)->kwal_info);

//		wrapfs_debug("[%lu]: [%s]\n",inode->i_ino, file_dentry(file)->d_name.name);
		down_write(&wi_target->redirection_tree_lock);
		target_ct = init_commit_tree(kwal_i, wi_target);
		now = wi_target->time;


		// migrate temp tree to commit tree
		down_write(&wf->redirection_tree_lock);
		hash_for_each_safe(wf->redirection_hash,i,tentry,entry,node){
				hash_del(&entry->node);
#ifdef RR_ISO
				list_del_init(&entry->next_active);
#endif
				list_del(&entry->next_entry);

				target_ct->remap_length +=
						add_redirection_entry_closed_txs(target_ct, entry->org_block, entry->new_block, entry->cs, now);

				kfree(entry);

		}
		hash_init(wf->redirection_hash);
		for(i=0; i<KWAL_NUM; i++){
				if(wf->written_kwals[i] == 1){
						if(atomic_dec_and_test(&kwal_i->kwals[i]->inflight_txs))
								wake_up_atomic_t(&kwal_i->kwals[i]->inflight_txs);
						wf->written_kwals[i] = 0;
				}
		}
		wf->is_tx =0;
		up_write(&wf->redirection_tree_lock);
		up_write(&wi_target->redirection_tree_lock);

no_tx:
		if (lower_file && lower_file->f_op && lower_file->f_op->flush) {
				filemap_write_and_wait(file->f_mapping);
				err = lower_file->f_op->flush(lower_file, id);
		}
//			wrapfs_debug("end\n");
		return err;
#if 0

		//  wrapfs_debug("unlock\n");

		//    mutex_lock(&kwal_i->atomic_mutex);

		down_write(&wi_target->redirection_tree_lock);

		if(target_ct->remap_length == 0){

				hash_for_each_safe(target_ct->redirection_hash,i,tentry,entry,node){
						list_del_init(&entry->neighbour);
						hash_del(&entry->node);
						kfree(entry);
				}
				hash_init(target_ct->redirection_hash);
				wi_target->commit_tree = NULL;
				up_write(&wi_target->redirection_tree_lock);
				goto release_end;
		}

		// do remap
		offset_array = (unsigned long*)kmalloc(sizeof(unsigned long)*(target_ct->remap_length)*2, GFP_KERNEL);
		//      printk("M [%X]+%d offset_array\n",offset_array, sizeof(unsigned long)*(target_ct->remap_length));

		for(i=0; i<KWAL_NUM; i++){
				kwal_file = (struct file *) kwal_i->kwals[i]->kwal_file;
				size = 0;

				list_for_each_entry_safe(entry, tentry, &target_ct->kwal_list[i], neighbour){

						hash_del(&entry->node);
						list_del_init(&entry->neighbour);

						offset_array[size++] = entry->org_block;
						offset_array[size++] = get_kwal_blk(entry->new_block);

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
				copy_kwal(wrapfs_lower_inode(inode), offset_array, size/2, kwal_file);
		}
		hash_init(target_ct->redirection_hash);

		wi_target->commit_tree = NULL;
		// make handle before calling remap_kwal()
		up_write(&wi_target->redirection_tree_lock);
		// before closing handle, journal metablock

release_end:    
		down_write(&kwal_i->commit_tree_lock);
		if(list_empty(&(target_ct->list))){
				up_write(&kwal_i->commit_tree_lock);
				BUG();
		}
		list_del_init (&(target_ct->list));
		up_write(&kwal_i->commit_tree_lock);

		//    mutex_unlock(&kwal_i->atomic_mutex);

		// log remapped information
		// log inode number, length = 0xFFFFFFFF

		kfree(offset_array);
		kfree(target_ct);

		return err;
#endif
}
static int compare_offset(const void *a, const void *b)
{
	if (*(unsigned long *)a < *(unsigned long *)b)
		return -1;
	if (*(unsigned long *)a > *(unsigned long *)b)
		return 1;
	return 0;
}
/* release all lower object references & free the file info structure */
static int wrapfs_file_release(struct inode *inode, struct file *file)
{
		struct file *lower_file;

		lower_file = wrapfs_lower_file(file);
		if (lower_file) {

//				#if 0

				struct inode *lower_inode;
				struct wrapfs_inode_info *wi_target = WRAPFS_I(inode);
				struct commit_tree_list* target_ct;


//				        wrapfs_debug("start\n");
				//        wrapfs_debug("[%lu]: [%s]\n",inode->i_ino, file_dentry(file)->d_name.name);

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

						//         wrapfs_debug("[%lu]: c-tree check\n", inode->i_ino);

						if(target_ct->inode != inode){
								BUG();
								//              wrapfs_debug("target_ct error!\n");
						}

						// del commit tree entry
						down_write(&kwal_i->commit_tree_lock);
						//            wrapfs_debug("del_s\n");
						list_del_init(&target_ct->list);
						//            wrapfs_debug("del_e\n");
						up_write(&kwal_i->commit_tree_lock);
						//      printk("ext4_destroy_inode\n");



						down_write(&wi_target->redirection_tree_lock);
						target_ct = wi_target->commit_tree; // reload
						if(target_ct == NULL){
								wrapfs_debug("null\n");
								up_write(&wi_target->redirection_tree_lock);
								goto end_wrapfs_file_release;
						}
						if(target_ct->remap_length == 0){
								wrapfs_debug("[%lu]: len=0\n", inode->i_ino);
								wi_target->commit_tree = NULL;
								up_write(&wi_target->redirection_tree_lock);
								kfree(target_ct);
								goto end_wrapfs_file_release;
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
//								if(size!=0)
//									sort(offset_array, size/2, sizeof(unsigned long)*2, compare_offset, NULL);

#ifdef F2FS_REMAP
								f2fs_remap_kwal(wrapfs_lower_inode(inode), offset_array, size/2, kwal_file);
								f2fs_remap_end(wrapfs_lower_inode(inode));
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

end_wrapfs_file_release:
				//		wrapfs_debug("%lu size\n",i_size_read(wrapfs_lower_inode(inode)));
//				        wrapfs_debug("end\n");
#ifdef COPY_CP
				wi_target->i_file = NULL;
#endif

//				#endif
				wrapfs_set_lower_file(file, NULL);
				fput(lower_file);
		}

		kfree(WRAPFS_F(file));
		return 0;
}

static int wrapfs_fsync(struct file *file, loff_t start, loff_t end,
				int datasync)
{
		int err;
		struct file *lower_file;
		struct path lower_path;
		struct dentry *dentry = file->f_path.dentry;

		err = __generic_file_fsync(file, start, end, datasync);
		if (err)
				goto out;
		lower_file = wrapfs_lower_file(file);
		wrapfs_get_lower_path(dentry, &lower_path);

		//	wrapfs_debug("[%s]\n", file_dentry(lower_file)->d_name.name);
		err = vfs_fsync_range(lower_file, start, end, datasync);
		wrapfs_put_lower_path(dentry, &lower_path);
out:
		return err;
}

static int wrapfs_fasync(int fd, struct file *file, int flag)
{
		int err = 0;
		struct file *lower_file = NULL;

		lower_file = wrapfs_lower_file(file);
		if (lower_file->f_op && lower_file->f_op->fasync)
				err = lower_file->f_op->fasync(fd, lower_file, flag);

		return err;
}
#if 0
/*
 * Wrapfs cannot use generic_file_llseek as ->llseek, because it would
 * only set the offset of the upper file.  So we have to implement our
 * own method to set both the upper and lower file offsets
 * consistently.
 */
static loff_t wrapfs_file_llseek(struct file *file, loff_t offset, int whence)
{
		int err;
		struct file *lower_file;

		err = generic_file_llseek(file, offset, whence);
		if (err < 0)
				goto out;

		lower_file = wrapfs_lower_file(file);
		err = generic_file_llseek(lower_file, offset, whence);

out:
		return err;
}
#endif


#include <linux/uio.h>

ssize_t wrapfs_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
		int err = -EINVAL;
		struct file *file, *lower_file;
		int ret = 0;
		struct inode *inode = iocb->ki_filp->f_path.dentry->d_inode;
		struct wrapfs_inode_info *wi = WRAPFS_I(inode);
		struct wrapfs_file_info * wf;
		struct iovec *iov = iter->iov;
		loff_t pos = iocb->ki_pos;
		loff_t oldpos = pos;
		int redirection = 1;
		struct iov_iter temp_iter;
		int now;

		file = iocb->ki_filp;
		lower_file = wrapfs_lower_file(file);
		if (!lower_file->f_op->read_iter) {
				err = -EINVAL;
				goto out;
		}

		/*
		 * It appears safe to rewrite this iocb, because in
		 * do_io_submit@fs/aio.c, iocb is a just copy from user.
		 */

		//before real read..
		get_file(lower_file); /* prevent lower_file from being released */
		iocb->ki_filp = lower_file;
		wf = WRAPFS_F(file);

		//KWAL start
		//	wrapfs_debug("read [%s] %llu+%lu\n", file_dentry(file)->d_name.name, pos, iov->iov_len);
//		wrapfs_debug("[%lu] %llu+%lu\n", inode->i_ino, pos, iov->iov_len);

		down_read(&wi->redirection_tree_lock);
		down_read(&wf->redirection_tree_lock);
		// check tx_writing
		if((wf->is_tx != 0) || (wi->commit_tree!= NULL))
		{
				//redireciton read
				struct kwal_info *kwal_i;
				struct file *temp_file;
				struct redirection_entry *redirection_result;
				struct page *page;
				loff_t old_pos, new_pos;
				pgoff_t index, new_index, last_index;
				int multipage=0;

				kwal_i = &(WRAPFS_SB(inode->i_sb)->kwal_info);

				index = pos >> PAGE_SHIFT;
				last_index = (pos + (iov->iov_len) -1) >> PAGE_SHIFT;
				old_pos = pos & (PAGE_SIZE - 1);
				//		wrapfs_debug("old index %lu, old pos %lu\n", index, old_pos);

				if(wf->is_tx){
						now=wf->start_time;
				}else{
						now=INT_MAX;
				}

//				while(last_index > (index+multipage) )
//						multipage++;

				multipage = last_index - index;

				if(multipage == 0){

						// check temp tree
						redirection_result = blk_redirection_ongoing_tx(wf, index);

						if(redirection_result != NULL)
						{
								// exist in temp tree
								new_index = get_kwal_blk(redirection_result->new_block);
								new_pos = new_index << PAGE_SHIFT;
								new_pos |= old_pos;
								//				wrapfs_debug("new index %lu, new pos %lu\n", new_index, new_pos);

								iocb->ki_filp = kwal_i->kwals[get_kwal_num(redirection_result->new_block)]->kwal_file;
								iocb->ki_pos = new_pos;
								pos = new_pos;

								//				wrapfs_debug("find block on temp tree\n");
								up_read(&wf->redirection_tree_lock);
								up_read(&wi->redirection_tree_lock);
								goto normal_read;
						}
						else
						{

								redirection_result = blk_redirection_closed_txs(wi->commit_tree, index, now);

								//				wrapfs_debug("unlockB\n");

								if(redirection_result != NULL){
										// exist in committed tree
										new_index = get_kwal_blk(redirection_result->new_block);
										new_pos = new_index << PAGE_SHIFT;
										new_pos |= old_pos;
										//					wrapfs_debug("new index %lu, new pos %lu\n", new_index, new_pos);


										iocb->ki_filp = kwal_i->kwals[get_kwal_num(redirection_result->new_block)]->kwal_file;
										iocb->ki_pos = new_pos;
										pos = new_pos;
#ifdef RR_ISO
										if(wf->read_cache_blk == index)
											if(wf->read_cache_time != redirection_result->endt)
												BUG();
										wf->read_cache_blk = index;
										wf->read_cache_time = redirection_result->endt;
#endif
										//					wrapfs_debug("find block on commit tree\n");
								}
								else
								{
										if(wf->read_cache_blk == index){
											wrapfs_debug("bug rR [%lu] %llu+%lu\n", iocb->ki_filp->f_path.dentry->d_inode->i_ino, iocb->ki_pos,  iov->iov_len);
										}
										//normal read
										//				wrapfs_debug("normal read\n");
										redirection = 0;
										up_read(&wf->redirection_tree_lock);
										up_read(&wi->redirection_tree_lock);
								}
						}
				}else {
						// multipage read
						int i;
						int n_iov=0;
						struct iovec *iov_list;
						int last_file = -2;
						int cur_file = -2;
#define ORGFILE		(-1)

						unsigned long last_converted_index;
						struct redirection_entry* cur_entry;
						loff_t partial_read = 0;
						int append = 0;

						wrapfs_debug("multipage read\n");

						iov_list = (struct iovec *) kmalloc(sizeof(struct iovec) * (multipage+1), GFP_KERNEL);
						memset(iov_list, 0 , sizeof(struct iovec) * (multipage+1));

						if ((pos & (PAGE_SIZE - 1)) != 0){
								// partial read on first page
								iov_list[0].iov_len = PAGE_SIZE - (pos & (PAGE_SIZE - 1));
						}else{
								// full read on first page
								iov_list[0].iov_len = PAGE_SIZE;
						}
						iov_list[0].iov_base = iov->iov_base;

						partial_read = (pos+iov->iov_len) & (PAGE_SIZE - 1);
						wrapfs_debug("partial_read [%lu]\n", partial_read);

						//setting first index
						cur_entry = blk_redirection_ongoing_tx(wf, index);
						if (NULL != cur_entry){
								// temp tree
								cur_file = get_kwal_num(cur_entry->new_block);
								wrapfs_debug("first index --> [%lu] temp tree\n", cur_entry->new_block);
						} else {
								cur_entry = blk_redirection_closed_txs(wi->commit_tree, index, now);

								if (NULL != cur_entry){
										// committed tree
										cur_file = get_kwal_num(cur_entry->new_block);
										wrapfs_debug("first index --> [%lu] committed tree\n", cur_entry->new_block);
								} else {
										// org file
										cur_file = ORGFILE;
										wrapfs_debug("first index --> [%lu] org tree\n", index);
								}
						}

						if((cur_file > ORGFILE)){
								new_index = get_kwal_blk(cur_entry->new_block);
								new_pos = new_index << PAGE_SHIFT;
								new_pos |= old_pos;

								iocb->ki_filp = kwal_i->kwals[get_kwal_num(cur_entry->new_block)]->kwal_file;

								last_converted_index = new_index;
						}
						else{
								new_pos = oldpos;
								iocb->ki_filp = lower_file;
								last_converted_index = index;
						}

						//			wrapfs_debug("ki_pos [%lu]\n", new_pos);
						iocb->ki_pos = new_pos;
						pos = new_pos;
						last_file = cur_file;

						for(i=1; i < multipage+1; i++){
								append = 0;
								cur_entry = blk_redirection_ongoing_tx(wf, index+i);

								if (NULL != cur_entry){
										// temp tree
										cur_file = get_kwal_num(cur_entry->new_block);
										wrapfs_debug("[%d] index --> [%lu] temp tree\n", i, cur_entry->new_block);
								}
								else
								{

										cur_entry = blk_redirection_closed_txs(wi->commit_tree, index+i, now);

										if (NULL != cur_entry){
												// committed tree
												cur_file = get_kwal_num(cur_entry->new_block);
												wrapfs_debug("[%d] index --> [%lu] committed tree\n", i, cur_entry->new_block);
										} else {
												// org file
												cur_file = ORGFILE;
												wrapfs_debug("[%d] index --> [%d] org tree\n", i, index+i);
										}
								}

								// Concatenated read
								if(last_file == cur_file){
										if((cur_file > ORGFILE) && ((last_converted_index+1) == get_kwal_blk(cur_entry->new_block))){
												//appending
												append = 1;
												wrapfs_debug("kwal append\n");
										}
										else if( (cur_file == ORGFILE) && ( (last_converted_index+1) == index+i)){
												//appending
												append = 1;
												wrapfs_debug("org append\n");
										}else {
												//no append
												append = 0;
										}
								}else { // last_file != cur_file
										//no append
										append = 0;
								}

								if(multipage == i)
										continue;

								if(append == 1){
										iov_list[n_iov].iov_len += PAGE_SIZE;
										wrapfs_debug("append iov_len[%lu]\n", iov_list[n_iov].iov_len);
								}else{
										//send read request
										int out;

										wrapfs_debug("send req [%s]file %llu+%lu\n", file_dentry(iocb->ki_filp)->d_name.name, iocb->ki_pos, iov_list[n_iov].iov_len);
										iov_iter_init(&temp_iter, READ, &iov_list[n_iov],1,iov_list[n_iov].iov_len);

										out = iocb->ki_filp->f_op->read_iter(iocb, &temp_iter);
										if(out<0){
											ret = out;
											goto kwal_read_err;
										}

										ret +=out;

										//setting current read request
										iov_list[n_iov+1].iov_len = PAGE_SIZE;
										iov_list[n_iov+1].iov_base = iov_list[n_iov].iov_base + iov_list[n_iov].iov_len;
										n_iov++;

										last_file = cur_file;
										if(cur_file > ORGFILE){
												new_index = get_kwal_blk(cur_entry->new_block);
												new_pos = new_index << PAGE_SHIFT;
												iocb->ki_filp = kwal_i->kwals[get_kwal_num(cur_entry->new_block)]->kwal_file;
										}
										else{
												new_pos = (index+i) << PAGE_SHIFT;
												iocb->ki_filp = lower_file;
										}
										iocb->ki_pos = new_pos;
										pos = new_pos;
								}

								if(cur_file > ORGFILE)
										last_converted_index = get_kwal_blk(cur_entry->new_block);
								else
										last_converted_index = index+i;
						}

						if(append == 1){
								int out;
								if(partial_read != 0)
										iov_list[n_iov].iov_len += partial_read;
								else
										iov_list[n_iov].iov_len += PAGE_SIZE;

								iov_iter_init(&temp_iter, READ, &iov_list[n_iov],1,iov_list[n_iov].iov_len);
								out = iocb->ki_filp->f_op->read_iter(iocb, &temp_iter);
								if(out<0){
									ret = out;
									goto kwal_read_err;
								}
								ret += out;

						}else{
								int out;
								iov_iter_init(&temp_iter, READ, &iov_list[n_iov],1,iov_list[n_iov].iov_len);
								out = iocb->ki_filp->f_op->read_iter(iocb, &temp_iter);
								if(out<0){
									ret = out;
									goto kwal_read_err;
								}
								ret += out;

								if(partial_read != 0)
										iov_list[n_iov+1].iov_len = partial_read;
								else
										iov_list[n_iov+1].iov_len = PAGE_SIZE;
								iov_list[n_iov+1].iov_base = iov_list[n_iov].iov_base + iov_list[n_iov].iov_len;
								n_iov++;

								if(cur_file > ORGFILE){
										new_index = get_kwal_blk(cur_entry->new_block);
										new_pos = new_index << PAGE_SHIFT;

										iocb->ki_filp = kwal_i->kwals[get_kwal_num(cur_entry->new_block)]->kwal_file;
								}
								else{
										new_pos = (index+i) << PAGE_SHIFT;
										iocb->ki_filp = lower_file;
								}
								iocb->ki_pos = new_pos;
								pos = new_pos;

								iov_iter_init(&temp_iter, READ, &iov_list[n_iov],1,iov_list[n_iov].iov_len);
								out = iocb->ki_filp->f_op->read_iter(iocb, &temp_iter);
								if(out<0){
									ret = out;
									goto kwal_read_err;
								}
								ret += out;
						}

						kfree(iov_list);
						if(ret < 0){
kwal_read_err:
								printk("send req [%s]file ino %u %llu+%lu\n", file_dentry(iocb->ki_filp)->d_name.name, file_inode(iocb->ki_filp)->i_ino, iocb->ki_pos,iov->iov_len);
								printk("err: %d", ret);
								BUG();
						}
						iocb->ki_filp = file;
						iocb->ki_pos =	oldpos + ret;
						up_read(&wf->redirection_tree_lock);
						up_read(&wi->redirection_tree_lock);
						fput(lower_file);

						/* update upper inode atime as needed */
						if (ret >= 0 || ret == -EIOCBQUEUED)
								fsstack_copy_attr_atime(file->f_path.dentry->d_inode,
												lower_file->f_path.dentry->d_inode);

						//        	wrapfs_debug("end\n");
						return ret;
				}

		}
		else{
				wrapfs_debug("send req [%s]file %llu+%lu\n", file_dentry(iocb->ki_filp)->d_name.name, iocb->ki_pos,iov->iov_len);
				redirection = 0;
				up_read(&wf->redirection_tree_lock);
				up_read(&wi->redirection_tree_lock);
		}

		//	wrapfs_debug("submit start\n");
normal_read:
		iov_iter_init(&temp_iter, READ, iov,1, iov->iov_len);
//		wrapfs_debug("rR [%lu] %llu+%lu\n", iocb->ki_filp->f_path.dentry->d_inode->i_ino, iocb->ki_pos,  iov->iov_len);
		//    wrapfs_debug("submit start\n");
		ret = iocb->ki_filp->f_op->read_iter(iocb, &temp_iter);
		//    wrapfs_debug("submit end\n");

		if (redirection){
				up_read(&wf->redirection_tree_lock);
				up_read(&wi->redirection_tree_lock);
		}


		//	ret = iocb->ki_filp->f_op->aio_read(iocb, iov, nr_segs, pos);
		//    wrapfs_debug("send read [%s]file %llu+%lu\n",file_dentry(iocb->ki_filp)->d_name.name, pos, iov->iov_len);


		if(ret < 0){
				printk("%d\n",ret);
				BUG();
		}

		iocb->ki_filp = file;
		iocb->ki_pos =	oldpos + ret;


		fput(lower_file);
		/* update upper inode atime as needed */
		if (ret >= 0 || ret == -EIOCBQUEUED)
				fsstack_copy_attr_atime(file->f_path.dentry->d_inode,
								lower_file->f_path.dentry->d_inode);

		//        wrapfs_debug("read end\n");
out:
		return ret;
}

#if 0
/*
 * Wrapfs read_iter, redirect modified iocb to lower read_iter
 */
ssize_t
		wrapfs_read_iter(struct kiocb *iocb, struct iov_iter *iter)
		{
				int err;
				struct file *file = iocb->ki_filp, *lower_file;

				lower_file = wrapfs_lower_file(file);
				if (!lower_file->f_op->read_iter) {
						err = -EINVAL;
						goto out;
				}

				get_file(lower_file); /* prevent lower_file from being released */
				iocb->ki_filp = lower_file;
				err = lower_file->f_op->read_iter(iocb, iter);
				iocb->ki_filp = file;
				fput(lower_file);
				/* update upper inode atime as needed */
				if (err >= 0 || err == -EIOCBQUEUED)
						fsstack_copy_attr_atime(d_inode(file->f_path.dentry),
										file_inode(lower_file));
out:
				return err;
		}
#endif

ssize_t
wrapfs_write_iter(struct kiocb *iocb, struct iov_iter *iter){
	int err = -EINVAL;
	struct file *file, *lower_file;
	struct inode *inode = iocb->ki_filp->f_path.dentry->d_inode;
	struct inode *lower_inode;
	int unaligned_aio = 0;
	//DJ
	struct iovec *iov = iter->iov;
	loff_t pos = iocb->ki_pos;
	loff_t oldpos = pos;
	struct iov_iter temp_iter;
	struct wrapfs_inode_info *wi = WRAPFS_I(inode);
	struct wrapfs_file_info *wf;
	struct kwal_node *this_kwal;
	struct redirection_entry *entry, *tentry;
	int multipage=0;
	unsigned long *orglist;
	unsigned long *tmplist;
	struct redirection_entry **redlist;
	u32 *cslist;
#ifdef FINEWC_DETECT
	u64 *dirtybitmaplist;
#endif
	int i;
	int now;


	file = iocb->ki_filp;
	lower_file = wrapfs_lower_file(file);
	lower_inode = wrapfs_lower_inode(inode);

	if (!lower_file->f_op->write_iter) {
			err = -EINVAL;
			goto out;
	}
	/*
	 * It appears safe to rewrite this iocb, because in
	 * do_io_submit@fs/aio.c, iocb is a just copy from user.
	 */

	//before real read..
	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;

	//KWAL write
	wf = WRAPFS_F(file);
	//	wrapfs_debug("write [%s] %llu+%lu\n", file_dentry(file)->d_name.name, pos, iov->iov_len);
	wrapfs_debug("[%lu] %llu+%lu\n", inode->i_ino, pos, iov->iov_len);

	down_read(&wi->redirection_tree_lock);
	down_read(&wf->redirection_tree_lock);
	// check tx_writing
	if((wf->is_tx != 0) || (wi->commit_tree != NULL))
	{
			//redireciton write
			//in place update --> out-of-place update
			struct kwal_info *kwal_i;
			struct file *temp_file=NULL;
			struct inode* kwal_inode;
			struct redirection_entry *o2t_entry, *committed_entry;
			struct page *page, *new_page;
			loff_t old_pos, new_pos;
			pgoff_t index, new_index, last_index;

			//			wrapfs_debug("multipage write\n");

			if(wf->is_tx)
					now = wf->start_time;
			else
					now = INT_MAX;

			up_read(&wf->redirection_tree_lock);
			up_read(&wi->redirection_tree_lock);

			//		wrapfs_debug("lockA\n");
			kwal_i = &(WRAPFS_SB(inode->i_sb)->kwal_info);

			//		wrapfs_debug("kwal write pos: %lld+%lu [%s]\n", pos, iov->iov_len, oldfilp->f_path.dentry->d_name.name);

			index = pos >> PAGE_SHIFT;
			last_index = (pos + (iov->iov_len) -1) >> PAGE_SHIFT;
			old_pos = pos & (PAGE_SIZE - 1);

//			while(last_index > (index+multipage) )
//					multipage++;

			multipage = last_index - index;

			orglist = (unsigned long *) kmalloc(sizeof(unsigned long) * (multipage+1), GFP_KERNEL);
			tmplist = (unsigned long *) kmalloc(sizeof(unsigned long) * (multipage+1), GFP_KERNEL);
			cslist = (u32 *) kmalloc(sizeof(u32) * (multipage+1), GFP_KERNEL);
			redlist = (struct redirection_entry **) kmalloc(sizeof(struct redirection_entry*) * (multipage+1), GFP_KERNEL);
#ifdef FINEWC_DETECT
			dirtybitmaplist = (u64 *) kmalloc(sizeof(u64) * (multipage+1), GFP_KERNEL);
			get_dirtybitmap(dirtybitmaplist, pos, iov->iov_len);
#endif

#if (KWAL_NUM <= 2)
			down_read(&kwal_i->big_kwal_mutex);
#endif

			//		wrapfs_debug("lockB\n");
			if(multipage == 0){
					// Check temp redirection tree

					down_read(&wf->redirection_tree_lock);
					o2t_entry = blk_redirection_ongoing_tx(wf, index);
					up_read(&wf->redirection_tree_lock);

					//			wrapfs_debug("temp tree checking\n");

					orglist[0] = index;

					if(o2t_entry == NULL){
							// no entry in temp tree

							// let's go kwal allocation
							// TODO: how about kwal alloc on tx_start()
							spin_lock(&kwal_i->curr_kwal_lock);

							this_kwal = kwal_i->curr_kwal;
							if(wf->written_kwals[this_kwal->num] == 0){
									wf->written_kwals[this_kwal->num] = 1;
									atomic_inc(&this_kwal->inflight_txs);
							}
							spin_unlock(&kwal_i->curr_kwal_lock);


							spin_lock(&this_kwal->last_block_lock);
#ifndef SEQ_META
							if(((KWAL_SIZE)/KiB(4) > this_kwal->last_block) && (this_kwal->index_block <= (this_kwal->last_block+2))){
									this_kwal->last_block = KWAL_SIZE/KiB(4)+1;
									WARN_ON_ONCE(1);
									//					wrapfs_debug("overflowA [%llu]\n", this_kwal->last_block);
							}
#endif
							tmplist[0] = this_kwal->last_block;
							temp_file = this_kwal->kwal_file;
							tmplist[0] |= (((unsigned int)(this_kwal->num)) << 28) ;
							new_index = this_kwal->last_block;
							this_kwal->last_block++;
							//				if(tmplist[0] > KWAL_SIZE/KiB(4))
							//					wrapfs_debug("[%lu]\n", tmplist[0]);
#ifndef SEQ_META
							this_kwal->remained = this_kwal->index_block - this_kwal->last_block;
#endif
							spin_unlock(&this_kwal->last_block_lock);

							down_read(&this_kwal->on_io); // ? why use this sem, here?
							if (((pos & (PAGE_SIZE - 1)) != 0) || (((pos+iov->iov_len) & (PAGE_SIZE - 1)) != 0)) {

									//check committed file
									down_read(&wi->redirection_tree_lock);
									committed_entry = blk_redirection_closed_txs(wi->commit_tree, index, now);

									if(committed_entry == NULL){
											//no entry in kwal file

											up_read(&wi->redirection_tree_lock);
											//search org file page cache
											page = find_get_page(lower_inode->i_mapping, index);

											if(page == NULL){
													// no cached page
													//read page
													filler_t *filler = (filler_t *)lower_inode->i_mapping->a_ops->readpage;
													//							wrapfs_debug("read-copy org data\n");
													page = read_cache_page(lower_inode->i_mapping ,index, filler, NULL);

													if (!IS_ERR(page))
															if (PageError(page))
																	BUG();

													new_page = grab_cache_page_write_begin(temp_file->f_mapping, new_index, 0);
													copy_highpage(new_page, page);
													put_page(page);
													SetPageUptodate(new_page);
													unlock_page(new_page);
													put_page(new_page);
											}else{
													// cached page

													//						wrapfs_debug("copy org data\n");
													new_page = grab_cache_page_write_begin(temp_file->f_mapping, new_index, 0);
													copy_highpage(new_page, page);
													put_page(page);
													SetPageUptodate(new_page);
													unlock_page(new_page);
													put_page(new_page);
											}

									}else{
											struct file* committed_kwal_file;
											struct inode *committed_kwal_inode;
											// data is located in kwal file
											pgoff_t committed_index;

											committed_kwal_file = (struct file*)kwal_i->kwals[get_kwal_num(committed_entry->new_block)]->kwal_file;
											committed_kwal_inode = file_inode(committed_kwal_file);
											committed_index = (unsigned long) get_kwal_blk(committed_entry->new_block);


											page = find_get_page(committed_kwal_inode->i_mapping, committed_index);

											if(page == NULL){
													//read page
													filler_t *filler = (filler_t *)committed_kwal_inode->i_mapping->a_ops->readpage;
													//							wrapfs_debug("read-copy wal data\n");
													page = read_cache_page(committed_kwal_inode->i_mapping ,committed_index, filler, NULL);

													new_page = grab_cache_page_write_begin(temp_file->f_mapping, new_index, 0);
													copy_highpage(new_page, page);
													put_page(page);
													SetPageUptodate(new_page);
													unlock_page(new_page);
													put_page(new_page);
											}else{
													// cached page

													//					wrapfs_debug("copy wal data\n");
													new_page = grab_cache_page_write_begin(temp_file->f_mapping, new_index, 0);
													copy_highpage(new_page, page);
													put_page(page);
													SetPageUptodate(new_page);
													unlock_page(new_page);
													put_page(new_page);
											}
											up_read(&wi->redirection_tree_lock);
									}

							}else{
									wrapfs_debug("skip_rmw\n");
							}
					}else{
							// already in temp tree
							this_kwal=kwal_i->kwals[get_kwal_num(o2t_entry->new_block)];
							down_read(&this_kwal->on_io);
							//				wrapfs_debug("uncommitted wal data\n");
							new_index = get_kwal_blk(o2t_entry->new_block);
							tmplist[0] = o2t_entry->new_block;
							temp_file = kwal_i->kwals[get_kwal_num(o2t_entry->new_block)]->kwal_file;
					}
					new_pos = new_index << PAGE_SHIFT;
					new_pos |= old_pos;

					//			wrapfs_debug("new pos %d\n", new_pos);

					iocb->ki_filp = temp_file;
					iocb->ki_pos = new_pos;
					pos = new_pos;
			}
			else {
					// multipage start---
					int i;

					spin_lock(&kwal_i->curr_kwal_lock);

					this_kwal = kwal_i->curr_kwal;
					if(wf->written_kwals[this_kwal->num] == 0){
							wf->written_kwals[this_kwal->num] = 1;
							atomic_inc(&this_kwal->inflight_txs);
					}
					spin_unlock(&kwal_i->curr_kwal_lock);


					spin_lock(&this_kwal->last_block_lock);
#ifndef SEQ_META
					if((KWAL_SIZE/KiB(4) > this_kwal->last_block) && (this_kwal->index_block <= (this_kwal->last_block+multipage+2))){
							this_kwal->last_block = KWAL_SIZE/KiB(4)+1;
							WARN_ON_ONCE(1);
					}
#endif
					new_index = this_kwal->last_block;
					temp_file = this_kwal->kwal_file;
					for(i=0; i < multipage+1; i++){
							orglist[i] = index+i;
							tmplist[i] = this_kwal->last_block++;
							tmplist[i] |= (((unsigned int)(this_kwal->num)) << 28);
					}
#ifndef SEQ_META
					this_kwal->remained = this_kwal->index_block - this_kwal->last_block;
#endif
					spin_unlock(&this_kwal->last_block_lock);
					down_read(&this_kwal->on_io);

					if ((pos & (PAGE_SIZE - 1)) != 0){
							// read-modify-write on first block

							// non-committed entry check
							down_read(&wf->redirection_tree_lock);
							o2t_entry = blk_redirection_ongoing_tx(wf, index);
							up_read(&wf->redirection_tree_lock);

							if(o2t_entry != NULL){
									// data is located in kwal file
									struct file* committed_kwal_file;
									struct inode *committed_kwal_inode;
									pgoff_t temp_index;
									committed_kwal_file = (struct file*)kwal_i->kwals[get_kwal_num(o2t_entry->new_block)]->kwal_file;
									committed_kwal_inode = file_inode(committed_kwal_file);

									temp_index = (unsigned long) get_kwal_blk(o2t_entry->new_block);

									//					wrapfs_debug("kwal file read\n");

									page = find_get_page(committed_kwal_inode->i_mapping, temp_index);

									if(page == NULL){
											//read page
											filler_t *filler = (filler_t *)committed_kwal_inode->i_mapping->a_ops->readpage;
											//							wrapfs_debug("allocated on kwal file\n");
											page = read_cache_page(committed_kwal_inode->i_mapping ,temp_index, filler, NULL);

											new_page = grab_cache_page_write_begin(temp_file->f_mapping, new_index, 0);
											copy_highpage(new_page, page);
											put_page(page);
											SetPageUptodate(new_page);
											unlock_page(new_page);
											put_page(new_page);
									}else{
											// cached page

											//						wrapfs_debug("copy wal data\n");
											new_page = grab_cache_page_write_begin(temp_file->f_mapping, new_index, 0);
											copy_highpage(new_page, page);
											put_page(page);
											SetPageUptodate(new_page);
											unlock_page(new_page);
											put_page(new_page);
									}
							}
							else{
									down_read(&wi->redirection_tree_lock);

									committed_entry = blk_redirection_closed_txs(wi->commit_tree, index, now);


									if(committed_entry == NULL){
											//no entry in kwal file
											up_read(&wi->redirection_tree_lock);

											//search org file page cache
											page = find_get_page(lower_inode->i_mapping, index);

											if(page == NULL){
													//read page
													filler_t *filler = (filler_t *)lower_inode->i_mapping->a_ops->readpage;
													//							wrapfs_debug("allocated\n");
													page = read_cache_page(lower_inode->i_mapping ,index, filler, NULL);

													new_page = grab_cache_page_write_begin(temp_file->f_mapping, new_index, 0);
													copy_highpage(new_page, page);
													put_page(page);
													SetPageUptodate(new_page);
													unlock_page(new_page);
													put_page(new_page);
											}else{
													// cached page
													new_page = grab_cache_page_write_begin(temp_file->f_mapping, new_index, 0);
													copy_highpage(new_page, page);
													put_page(page);
													SetPageUptodate(new_page);
													unlock_page(new_page);
													put_page(new_page);
											}

									}else{
											// data is located in kwal file
											pgoff_t committed_index;
											struct file* committed_kwal_file;
											struct inode *committed_kwal_inode;


											committed_kwal_file = (struct file*)kwal_i->kwals[get_kwal_num(committed_entry->new_block)]->kwal_file;
											committed_kwal_inode = file_inode(committed_kwal_file);

											committed_index = (unsigned long) get_kwal_blk(committed_entry->new_block);
											page = find_get_page(committed_kwal_inode->i_mapping, committed_index);

											if(page == NULL){
													//read page
													filler_t *filler = (filler_t *)committed_kwal_inode->i_mapping->a_ops->readpage;
													//				wrapfs_debug("allocated on kwal file\n");
													page = read_cache_page(committed_kwal_inode->i_mapping ,committed_index, filler, NULL);

													new_page = grab_cache_page_write_begin(temp_file->f_mapping, new_index, 0);
													copy_highpage(new_page, page);
													put_page(page);
													SetPageUptodate(new_page);
													unlock_page(new_page);
													put_page(new_page);
											}else{
													// cached page
													new_page = grab_cache_page_write_begin(temp_file->f_mapping, new_index, 0);
													copy_highpage(new_page, page);
													put_page(page);
													SetPageUptodate(new_page);
													unlock_page(new_page);
													put_page(new_page);
											}
											up_read(&wi->redirection_tree_lock);
									}
							}
					}

					if (((pos+iov->iov_len) & (PAGE_SIZE - 1)) != 0){
							// read-modify-write on last block
							// non-committed entry check
							down_read(&wf->redirection_tree_lock);
							o2t_entry = blk_redirection_ongoing_tx(wf, last_index);
							up_read(&wf->redirection_tree_lock);

							if(o2t_entry != NULL){
									// data is located in kwal file
									struct file* committed_kwal_file;
									struct inode *committed_kwal_inode;
									pgoff_t temp_index;

									committed_kwal_file = (struct file*)kwal_i->kwals[get_kwal_num(o2t_entry->new_block)]->kwal_file;
									committed_kwal_inode = file_inode(committed_kwal_file);

									temp_index = (unsigned long) get_kwal_blk(o2t_entry->new_block);

									//			wrapfs_debug("goto kwal file read\n");

									page = find_get_page(committed_kwal_inode->i_mapping, temp_index);

									if(page == NULL){
											//read page
											filler_t *filler = (filler_t *)committed_kwal_inode->i_mapping->a_ops->readpage;
											//			wrapfs_debug("allocated on kwal file\n");
											page = read_cache_page(committed_kwal_inode->i_mapping ,temp_index, filler, NULL);

											new_page = grab_cache_page_write_begin(temp_file->f_mapping, get_kwal_blk(tmplist[multipage]), 0);
											copy_highpage(new_page, page);
											put_page(page);
											SetPageUptodate(new_page);
											unlock_page(new_page);
											put_page(new_page);
									}else{
											// cached page
											new_page = grab_cache_page_write_begin(temp_file->f_mapping, get_kwal_blk(tmplist[multipage]), 0);
											copy_highpage(new_page, page);
											put_page(page);
											SetPageUptodate(new_page);
											unlock_page(new_page);
											put_page(new_page);
									}
							}
							else{

									down_read(&wi->redirection_tree_lock);

									committed_entry = blk_redirection_closed_txs(wi->commit_tree, index, now);


									if(committed_entry == NULL){
											//no entry in kwal file
											up_read(&wi->redirection_tree_lock);
											//search org file page cache
											page = find_get_page(lower_inode->i_mapping, last_index);

											if(page == NULL){
													//read page
													filler_t *filler = (filler_t *)lower_inode->i_mapping->a_ops->readpage;
													//						wrapfs_debug("allocated\n");
													page = read_cache_page(lower_inode->i_mapping ,last_index, filler, NULL);

													new_page = grab_cache_page_write_begin(temp_file->f_mapping, get_kwal_blk(tmplist[multipage]), 0);
													copy_highpage(new_page, page);
													put_page(page);
													SetPageUptodate(new_page);
													unlock_page(new_page);
													put_page(new_page);
											}else{
													// cached page
													new_page = grab_cache_page_write_begin(temp_file->f_mapping, get_kwal_blk(tmplist[multipage]), 0);
													copy_highpage(new_page, page);
													put_page(page);
													SetPageUptodate(new_page);
													unlock_page(new_page);
													put_page(new_page);
											}

									}else{
											// data is located in kwal file
											struct file* committed_kwal_file;
											struct inode *committed_kwal_inode;
											pgoff_t committed_index;

											committed_kwal_file = (struct file*)kwal_i->kwals[get_kwal_num(committed_entry->new_block)]->kwal_file;
											committed_kwal_inode = file_inode(committed_kwal_file);
											committed_index = (unsigned long) get_kwal_blk(committed_entry->new_block);

											page = find_get_page(committed_kwal_inode->i_mapping, committed_index);

											if(page == NULL){
													//read page
													filler_t *filler = (filler_t *)committed_kwal_inode->i_mapping->a_ops->readpage;
													//					wrapfs_debug("allocated on kwal file\n");
													page = read_cache_page(committed_kwal_inode->i_mapping ,committed_index, filler, NULL);

													new_page = grab_cache_page_write_begin(temp_file->f_mapping, get_kwal_blk(tmplist[multipage]), 0);
													copy_highpage(new_page, page);
													put_page(page);
													SetPageUptodate(new_page);
													unlock_page(new_page);
													put_page(new_page);
											}else{
													// cached page
													new_page = grab_cache_page_write_begin(temp_file->f_mapping, get_kwal_blk(tmplist[multipage]), 0);
													copy_highpage(new_page, page);
													put_page(page);
													SetPageUptodate(new_page);
													unlock_page(new_page);
													put_page(new_page);
											}
											up_read(&wi->redirection_tree_lock);
									}
							}
					}

					new_pos = new_index << PAGE_SHIFT;
					new_pos |= old_pos;

					//			wrapfs_debug("new pos %lu\n", new_pos);

					iocb->ki_filp = temp_file;
					iocb->ki_pos = new_pos;
					pos = new_pos;
			} // multi page write end
#if (KWAL_NUM <= 2)
			up_read(&kwal_i->big_kwal_mutex);
#endif
	}
	else{
			up_read(&wf->redirection_tree_lock);
			up_read(&wi->redirection_tree_lock);
	}
normal_write:

	//go write
	//	wrapfs_debug("rW [%lu] %llu+%lu\n", iocb->ki_filp->f_path.dentry->d_inode->i_ino, pos, iov->iov_len);
	iov_iter_init(&temp_iter, WRITE, iov,1, iov->iov_len);
	err = iocb->ki_filp->f_op->write_iter(iocb, &temp_iter);

	if(err != iov->iov_len){
			printk("%d %d\,",err, iov->iov_len);
			BUG();
	}
	if(lower_file != iocb->ki_filp){
			struct kwal_info *kwal_i;
			struct inode *kwal_inode;
			struct page* page;
			char *buf;
			filler_t *filler;

			kwal_inode = file_inode(iocb->ki_filp);

			filler = (filler_t *)kwal_inode->i_mapping->a_ops->readpage;
			//		wrapfs_debug("send write [%s]file %llu+%lu\n",file_dentry(iocb->ki_filp)->d_name.name, pos, iov->iov_len);
			iocb->ki_filp = file;
			iocb->ki_pos =  oldpos + (loff_t)err;
			if(wi->kwal_isize < iocb->ki_pos)
					wi->kwal_isize = iocb->ki_pos;

			kwal_i = &(WRAPFS_SB(inode->i_sb)->kwal_info);
			up_read(&this_kwal->on_io);
			//#if 0
			for(i=0; i < multipage+1; i++){
				// checksum add
				//			wrapfs_debug("r [%lu]\n", get_kwal_blk( tmplist[i]));
				page = find_lock_page(kwal_inode->i_mapping, get_kwal_blk(tmplist[i]));
				if(page == NULL)
						page = read_cache_page(kwal_inode->i_mapping ,get_kwal_blk(tmplist[i]), filler, NULL);
				if(page == NULL)
						BUG();
				buf = (char*) kmap_atomic(page);
				cslist[i] = crc32(0 ^ 0xffffffff, buf, PAGE_SIZE) ^ 0xffffffff;

				kunmap_atomic(buf);
				unlock_page(page);
				put_page(page);
				//			wrapfs_debug("cs [%X]\n", cslist[i]);
			}
			//#endif
			down_write(&wf->redirection_tree_lock);
			for(i=0; i < multipage+1; i++){
					wrapfs_debug("%lu->%lu\n", orglist[i], get_kwal_blk(tmplist[i]));
					redlist[i] = add_redirection_entry_ongoing_tx(wf, orglist[i], tmplist[i], cslist[i]);
			}
			up_write(&wf->redirection_tree_lock);


			if(wf->is_tx == 0){
					struct commit_tree_list * target_ct;
					int now;
					int i;

					down_write(&wi->redirection_tree_lock);

					target_ct = init_commit_tree(kwal_i, wi);

					now = wi->time;
					// migrate temp tree to commit tree
					down_write(&wf->redirection_tree_lock);

					list_for_each_entry_safe(entry, tentry, &wf->traversing_listhead, next_entry){
							hash_del(&entry->node);
							list_del(&entry->next_entry);
							//				wrapfs_debug("notx\n");
							target_ct->remap_length +=
									add_redirection_entry_closed_txs(target_ct, entry->org_block, entry->new_block, entry->cs, now);
							target_ct->written_length++;
							kfree(entry);
					}

					hash_init(wf->redirection_hash);
					for(i=0; i<KWAL_NUM; i++){
							if(wf->written_kwals[i] == 1){
									if(atomic_dec_and_test(&kwal_i->kwals[i]->inflight_txs))
											wake_up_atomic_t(&kwal_i->kwals[i]->inflight_txs);
									wf->written_kwals[i] = 0;
							}
					}
					up_write(&wf->redirection_tree_lock);
					up_write(&wi->redirection_tree_lock);
			}else{
				struct commit_tree_list * target_ct;
				int conflict = 0;
				down_write(&wi->redirection_tree_lock);

				target_ct = init_commit_tree(kwal_i, wi);
#ifdef FINEWC_DETECT
				for(i=0; i < multipage+1; i++){
					conflict += add_redirection_entry_staging_tree(target_ct, redlist[i], dirtybitmaplist[i]);
				}
#endif
				up_write(&wi->redirection_tree_lock);
				if(conflict > 0){
					wf->is_abort = 1;
				}
			}
			kfree(orglist);
			kfree(tmplist);
			kfree(cslist);
			kfree(redlist);
#ifdef FINEWC_DETECT
			kfree(dirtybitmaplist);
#endif
	}else{
			iocb->ki_filp = file;
			iocb->ki_pos =  oldpos + (loff_t)err;
	}

	fput(lower_file);

	/* update upper inode times/sizes as needed */
	if (err >= 0 || err == -EIOCBQUEUED) {
			fsstack_copy_inode_size(file->f_path.dentry->d_inode,
							lower_file->f_path.dentry->d_inode);
			fsstack_copy_attr_times(file->f_path.dentry->d_inode,
							lower_file->f_path.dentry->d_inode);
	}
out:
	if (err < 0)
			wrapfs_debug("err: %d\n",err);
	//	wrapfs_debug("end\n");
	return err;
}

#if 0
/*
 * Wrapfs write_iter, redirect modified iocb to lower write_iter
 */
ssize_t
		wrapfs_write_iter(struct kiocb *iocb, struct iov_iter *iter)
		{
				int err;
				struct file *file = iocb->ki_filp, *lower_file;

				lower_file = wrapfs_lower_file(file);
				if (!lower_file->f_op->write_iter) {
						err = -EINVAL;
						goto out;
				}

				get_file(lower_file); /* prevent lower_file from being released */
				iocb->ki_filp = lower_file;
				err = lower_file->f_op->write_iter(iocb, iter);
				iocb->ki_filp = file;
				fput(lower_file);
				/* update upper inode times/sizes as needed */
				if (err >= 0 || err == -EIOCBQUEUED) {
						fsstack_copy_inode_size(d_inode(file->f_path.dentry),
										file_inode(lower_file));
						fsstack_copy_attr_times(d_inode(file->f_path.dentry),
										file_inode(lower_file));
				}
out:
				return err;
		}
#endif

long wrapfs_fallocate(struct file *file, int mode, loff_t offset, loff_t len){
	int err;
	struct file *lower_file;
	lower_file = wrapfs_lower_file(file);

	if(!lower_file->f_op->fallocate)
			return -EOPNOTSUPP;

	err = lower_file->f_op->fallocate(lower_file, mode, offset, len);

	/* update our inode atime upon a successful lower read */
	if (err >= 0)
			fsstack_copy_inode_size(file->f_path.dentry->d_inode,
							lower_file->f_path.dentry->d_inode);

	return err;
}

/*
 * Wrapfs cannot use generic_file_llseek as ->llseek, because it would
 * only set the offset of the upper file.  So we have to implement our
 * own method to set both the upper and lower file offsets
 * consistently.
 */
static loff_t wrapfs_file_llseek(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file->f_mapping->host;
	struct inode *lower_inode = wrapfs_lower_inode(inode);
	struct wrapfs_inode_info *wi = WRAPFS_I(inode);
	loff_t i_size, err;
	loff_t lower_i_size;
	struct file *lower_file;
	int reset_val = 0;


	spin_lock(&inode->i_lock);
	i_size=i_size_read(inode);
	lower_i_size=i_size_read(lower_inode);
	if(wi->commit_tree != NULL){
			if(i_size < wi->kwal_isize){
					i_size_write(inode, wi->kwal_isize);
					i_size_write(lower_inode, wi->kwal_isize);
					reset_val = 1;
			}
	}


	err = generic_file_llseek(file, offset, whence);

	//	wrapfs_debug("1[%s] %d+%d+%d\n", file_dentry(file)->d_name.name, offset, whence, err);
	if (err < 0)
			goto out;

	lower_file = wrapfs_lower_file(file);


	err = generic_file_llseek(lower_file, err, 0);

	//	wrapfs_debug("2[%s] %d+%d+%d\n", file_dentry(lower_file)->d_name.name, offset, whence, err);
	if(reset_val){
			i_size_write(inode, i_size);
			i_size_write(lower_inode, lower_i_size);
	}


out:
	spin_unlock(&inode->i_lock);
	return err;
}



const struct file_operations wrapfs_main_fops = {
		.llseek		= wrapfs_file_llseek,
		//	.read		= wrapfs_read,
		//	.write		= wrapfs_write,
		.unlocked_ioctl	= wrapfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
		.compat_ioctl	= wrapfs_compat_ioctl,
#endif
		.fallocate  = wrapfs_fallocate,
		.mmap		= wrapfs_mmap,
		.open		= wrapfs_open,
		.flush		= wrapfs_flush,
		.release	= wrapfs_file_release,
		.fsync		= wrapfs_fsync,
		.fasync		= wrapfs_fasync,
		.read_iter	= wrapfs_read_iter,
		.write_iter	= wrapfs_write_iter,
};

/* trimmed directory options */
const struct file_operations wrapfs_dir_fops = {
		.llseek		= wrapfs_file_llseek,
		.read		= generic_read_dir,
		.iterate	= wrapfs_readdir,
		.unlocked_ioctl	= wrapfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
		.compat_ioctl	= wrapfs_compat_ioctl,
#endif
		.open		= wrapfs_open,
		.release	= wrapfs_file_release,
		.flush		= wrapfs_flush,
		.fsync		= wrapfs_fsync,
		.fasync		= wrapfs_fasync,
};
