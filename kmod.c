#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include "linux/mm.h"
#include <linux/debugfs.h>
#include <linux/mm_types.h>
#include <linux/pagemap.h>
#include <asm/page.h>
#include <linux/pid.h>
#include <asm/pgtable.h>
#include <linux/fd.h>
#include <linux/path.h>
#include <linux/mount.h>
#include <linux/file.h>
#include <linux/fs.h>

#define BUFFER_SIZE 1024

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("Ilinskaya");
MODULE_VERSION("1.0");

static struct dentry *kmod_root;
static struct dentry *kmod_args_file;
static struct dentry *kmod_result_file;
static struct page* struct_page;
static struct vfsmount* struct_vfsmount;

static int kmod_result_open(struct seq_file *sf, void *data);
struct page * kmod_get_page(void);
struct vfsmount * kmod_get_vfsmount(void);
void set_result(void);

int kmod_open(struct inode *inode, struct file *file) {
    return single_open(file, kmod_result_open, inode->i_private);
}
static ssize_t kmod_args_write( struct file* ptr_file, const char __user* buffer, size_t length, loff_t* ptr_offset );

static struct file_operations kmod_args_ops = {
        .owner   = THIS_MODULE,
        .read    = seq_read,
        .write   = kmod_args_write,
        .open = kmod_open,
};

static int fdesc = 0;
static int pid = 1;

struct page *get_page_by_mm_and_address(struct mm_struct* mm, long address) {
    pgd_t *pgd;
    p4d_t* p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    struct page *page = NULL;

    pgd = pgd_offset(mm, address);
    if (!pgd_present(*pgd)) {
        return NULL;
    }

    p4d = p4d_offset(pgd, address);
    if (!p4d_present(*p4d)) {
        return NULL;
    }

    pud = pud_offset(p4d, address);
    if (!pud_present(*pud)) {
        return NULL;
    }

    pmd = pmd_offset(pud, address);
    if (!pmd_present(*pmd)) {
        return NULL;
    }

    pte = pte_offset_kernel(pmd, address);
    if (!pte_present(*pte)) {
        return NULL;
    }

    page = pte_page(*pte);
    return page;
}

struct page * kmod_get_page() {
    struct task_struct *ts;
    struct mm_struct *mm;
    struct vm_area_struct *vm_current;
    struct page *page_struct;
    ts = get_pid_task(find_get_pid(pid), PIDTYPE_PID);
    mm = ts->mm;
    if (mm == NULL) {
        printk(KERN_INFO "kmod: process has no mm\n");
        return null;
    }
    vm_current = mm->mmap;
    long start = vm_current->vm_start;
    long end = vm_current->vm_start;
    long address = start;
    while (address <= end) {
        page_struct = get_page_by_mm_and_address(mm, address);
        address += PAGE_SIZE;
        if (page_struct != NULL){
            break;
        }
    }
    if (page_struct == NULL) {
        printk(KERN_INFO "kmod: error getting page\n");
        return null;
    }
    return page_struct;
}

struct vfsmount * kmod_get_vfsmount() {
    struct fd f = fdget(fdesc);
    if(!f.file) {
        printk(KERN_INFO "kmod: error opening file by descriptor\n");
    }
    struct vfsmount *vfs = f.file->f_path.mnt;
    return vfs;
}

void set_result() {
    struct_page = kmod_get_page();
    struct_vfsmount = kmod_get_vfsmount();
}

static int kmod_result_open(struct seq_file *sf, void *data) {
    printk(KERN_INFO "kmod: suicide\n");
    set_result();
    if (struct_page == NULL) {
        seq_printf (sf, "process has no mm =( \n");
    } else {
        seq_printf(sf, "-----PAGE-----\nflags: %ul\n", struct_page->flags);
        seq_printf(sf, "refcount:{ \n   counter: %u\n", struct_page->_refcount.counter);
        seq_printf(sf, "}\n\n");
    }
    seq_printf(sf, "-----VFSMOUNT-----\n");
    seq_printf(sf, "mnt_flags: %uc\n", struct_vfsmount->mnt_flags);
    seq_printf(sf, "superblock:{\n   blocksize_bits: %u\n", struct_vfsmount->mnt_sb->s_blocksize_bits);
    seq_printf(sf, "   blocksize: %lu\n", struct_vfsmount->mnt_sb->s_blocksize);
    seq_printf(sf, "   blocksize: %d\n", struct_vfsmount->mnt_sb->s_count);
    seq_printf(sf, "   blocksize: %ld\n", struct_vfsmount->mnt_sb->s_maxbytes);
    seq_printf(sf, "}\n");
    return 0;
}

static ssize_t kmod_args_write( struct file* ptr_file, const char __user* buffer, size_t length, loff_t* ptr_offset) {
    printk(KERN_INFO "kmod: get params\n");
    char kbuf[BUFFER_SIZE];

    if (*ptr_offset > 0 || length > BUFFER_SIZE) {
        return -EFAULT;
    }

    if ( copy_from_user(kbuf, buffer, length) ) {
        return -EFAULT;
    }
    int a = sscanf(kbuf, "%d", &fdesc);
    int b = sscanf(kbuf, "%d", &pid);
    printk(KERN_INFO "kmod: fdesc %d, pid %d.", fdesc, pid);
    ssize_t count = strlen(kbuf);
    *ptr_offset = count;
    return count;
}

static int __init kmod_init(void) {
    printk(KERN_INFO "kmod: module loaded =)\n");
    kmod_root = debugfs_create_dir("kmod", NULL);
    kmod_args_file = debugfs_create_file( "kmod_args", 0666, kmod_root, NULL, &kmod_args_ops );
    kmod_result_file = debugfs_create_file( "kmod_result", 0666, kmod_root, NULL, &kmod_args_ops );
    return 0;
}

static void __exit kmod_exit(void) {
    debugfs_remove_recursive(kmod_root);
    printk(KERN_INFO "kmod: module unloaded\n");
}
module_init(kmod_init);
module_exit(kmod_exit);
