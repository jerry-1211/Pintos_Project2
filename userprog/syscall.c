#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "userprog/syscall.h"
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "process.c"
#include "devices/input.c"
#include "lib/user/syscall.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
void halt(void);

struct lock filesys_lock; 


/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

    lock_init(&filesys_lock);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED) {

    // system call number 
    int sys_number = f->R.rax;

    // 레지스터에서 매개변수 꺼내오는 순서
    // %rdi %rsi %rdx %r10 %r8 %r9

    switch (sys_number) {
         case SYS_HALT:
            halt();
            break;
        case SYS_EXIT:
            exit(f->R.rdi);
            break;
        case SYS_FORK:
            f->R.rax = fork(f->R.rdi);
            break;
        case SYS_EXEC:
            f->R.rax = exec(f->R.rdi);
            break;
        case SYS_WAIT:
            f->R.rax = process_wait(f->R.rdi);
            break;
        case SYS_CREATE:
            f->R.rax = create(f->R.rdi, f->R.rsi);
            break;
        case SYS_REMOVE:
            f->R.rax = remove(f->R.rdi);
            break;
        case SYS_OPEN:
            f->R.rax = open(f->R.rdi);
            break;
        case SYS_FILESIZE:
            f->R.rax = filesize(f->R.rdi);
            break;
        case SYS_READ:
            f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
            break;
        case SYS_WRITE:
            f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
            break;
        case SYS_SEEK:
            seek(f->R.rdi, f->R.rsi);
            break;
        case SYS_TELL:
            f->R.rax = tell(f->R.rdi);
            break;
        case SYS_CLOSE:
            close(f->R.rdi);
            break;
        case SYS_DUP2:
            f->R.rax = dup2(f->R.rdi, f->R.rsi);
            break;
      
    }
}
	

void check_address(void *addr){
    struct thread *t = thread_current();
    if(!is_user_vaddr(addr) || addr == NULL || pml4_get_page(t->pml4,addr) == NULL){
        exit(-1);
    } 
}    

void halt(void) {
    power_off();
}

void exit(int status) {
    struct thread *curr = thread_current();
    curr->exit_status = status;

    /** #Project 2: Process Termination Messages */
    printf("%s: exit(%d)\n", curr->name, curr->exit_status);
    thread_exit();
}

/* 파일 생성 또는 삭제하는 시스템 콜 */
/* 성공이면 true, 실패면 false */
bool create (const char *file, unsigned initial_size) {

	check_address(file);
	if (filesys_create(file, initial_size)) {
		return true;
	}
	else {
		return false;
	}
}

bool remove (const char *file) {
	check_address(file);
	if (filesys_remove(file)) {
		return true;
	} else {
		return false;
	}
}

int open(const char *file){
    check_address(file);
    struct file *newfile = filesys_open(file);

    if(newfile==NULL){
        return -1;
    }

    int fd = process_add_file(newfile);
    
    if(fd == -1){
        file_close(newfile);
    }

    return fd; 
}

int filesize(int fd){
    struct file *f = process_get_file(fd); 
    if(f == NULL){
        return -1;
    }
    return file_length(f);
}

int read(int fd, void *buffer, unsigned length){
    check_address(buffer);

    // fd = 0은 stdin 
    if(fd == 0){
        int i = 0 ;
        char c ; 
        unsigned char *buf = buffer;
        for(;i<length; i++){
            c = input_getc();
            *buf++ = c;
            if(c == '\0'){
                break;
            }
        }
        return i;
   }

    if (fd < 3){
        return -1;
    }

    struct file *file = process_close_file(fd);
    off_t bytes = -1 ;

    if(file == NULL){
        return -1 ;
    }

    lock_acquire(&filesys_lock);
    bytes = file_read(file,buffer,length);
    lock_release(&filesys_lock);

    return bytes ; 

}

int write(int fd, const void *buffer, unsigned size){
    check_address(buffer);

    off_t bytes = -1;
    if(fd<=0){
        return -1;
    }

    if(fd<3){
        putbuf(buffer,size);
        return size;
    }

    struct file *file = process_get_file(fd);

    if(file == NULL){
        return -1;
    }

    lock_acquire(&filesys_lock);
    bytes = file_write(file,buffer,size); 
    lock_release(&filesys_lock); 

    return bytes;
}

void seek(int fd, unsigned position){
    struct file *file = process_get_file(fd);

    if(fd<3 || file == NULL){
        return ;
    }

    file_seek(file,position);
}

unsigned tell(int fd){
    struct file *file = process_get_file(fd);

    if(fd<3 || file == NULL){
        return ;
    }

    return file_tell(file);
}

void close(int fd){
    struct file *file = process_get_file(fd);

    if(fd<3 || file == NULL){
        return ;
    }

    process_close_file(fd);

    file_close(file);
}


pid_t fork(const char *thread_name){
    check_address(thread_name);
    return process_fork(thread_name,NULL);
}

int exec(const char *cmd_line){
    check_address(cmd_line);

    off_t size = strlen(cmd_line) + 1 ;
    char *cmd_copy = palloc_get_page(PAL_ZERO);

    if(cmd_copy == NULL){
        return -1;
    }

    memcpy(cmd_copy,cmd_line,size); 

    if(process_exec(cmd_copy) == -1){
        return -1;
    }

    return 0;
}

int wait(pid_t tid){
    return process_wait(tid);
}


int dup2(int oldfd, int newfd){
    if(oldfd < 0 || newfd < ){
        return -1;
    }
    struct file *oldfile = process_get_file(oldfd);

    if(oldfile == NULL){
        return -1 ;
    }

    struct file *newfile = process_get_file(newfd);

    if(oldfd == newfd){
        return newfd ;
    }

    close(newfd);  

    newfd = process_insert_file(newfd,oldfile); 
    
    return newfd;
}


process_insert_file(int fd, struct file *f) {
    struct thread *curr = thread_current();
    struct file **fdt = curr->fdt;

    if (fd < 0 || fd >= FDCOUNT_LIMIT){
        return -1;
    }
        
    if (f > STDERR){
        f->dup_count++;
    }

    fdt[fd] = f;

    return fd;
}