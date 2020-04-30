#ifndef REMAP_H
#define REMAP_H
extern void remap_kwal(struct inode *target_inode, unsigned long *offset_array, int size, struct file *temp_file);
extern void copy_kwal(struct inode *target_inode,unsigned long * offset_array,int size,struct file * wal_file);
extern void f2fs_remap_kwal(struct inode *db_inode, unsigned long  *offset, int count, struct file *wal_file);
extern void f2fs_remap_end(struct inode* inode);
extern void remap_extent_kwal(struct inode *target_inode, unsigned long *offset_array, int size, struct file *temp_file);
extern int check_kwal_extents(struct inode *inode);
extern int check_free_fragment(struct super_block *sb);
#endif
