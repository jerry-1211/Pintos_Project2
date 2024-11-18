#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

#include "filesys/filesys.h"
#include "include/lib/kernel/stdio.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081			/* Segment selector msr */
#define MSR_LSTAR 0xc0000082		/* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void syscall_init(void)
{
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
							((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			  FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED)
{
	int sys_number = f->R.rax; // rax: 시스템 콜 넘버

	switch (sys_number)
	{
	case SYS_HALT:
		halt();
	case SYS_EXIT:
		exit(f->R.rdi);
	case SYS_FORK:
		fork(f->R.rdi);
	case SYS_EXEC:
		exec(f->R.rdi);
	case SYS_WAIT:
		wait(f->R.rdi);
	case SYS_CREATE:
		create(f->R.rdi, f->R.rsi);
	case SYS_REMOVE:
		remove(f->R.rdi);
	case SYS_OPEN:
		open(f->R.rdi);
	case SYS_FILESIZE:
		filesize(f->R.rdi);
	case SYS_READ:
		read(f->R.rdi, f->R.rsi, f->R.rdx);
	case SYS_WRITE:
		write(f->R.rdi, f->R.rsi, f->R.rdx);
	case SYS_SEEK:
		seek(f->R.rdi, f->R.rsi);
	case SYS_TELL:
		tell(f->R.rdi);
	case SYS_CLOSE:
		close(f->R.rdi);
	}

	printf("system call!\n");
	thread_exit();
}

void check_address(void *addr)
{
	struct thread *t = thread_current();
	/* --- Project 2: User memory access --- */
	// if (!is_user_vaddr(addr)||addr == NULL)
	//-> 이 경우는 유저 주소 영역 내에서도 할당되지 않는 공간 가리키는 것을 체크하지 않음. 그래서
	// pml4_get_page를 추가해줘야!
	if (!is_user_vaddr(addr) || addr == NULL ||
		pml4_get_page(t->pml4, addr) == NULL)
	{
		exit(-1);
	}
}

void halt(void)
{
	power_off();
}

void exit(int status)
{
	struct thread *t = thread_current();
	t->exit_status = status;
	printf("%s: exit%d\n", t->name, status); // Process Termination Message
	/* 정상적으로 종료됐다면 status는 0 */
	/* status: 프로그램이 정상적으로 종료됐는지 확인 */
	thread_exit();
}

bool create(const char *file, unsigned initial_size)
{
	/* 성공이면 true, 실패면 false */
	check_address(file);
	if (filesys_create(file, initial_size))
	{
		return true;
	}
	else
	{
		return false;
	}
}

bool remove(const char *file)
{
	check_address(file);
	if (filesys_remove(file))
	{
		return true;
	}
	else
	{
		return false;
	}
}

int write(int fd, const void *buffer, unsigned size)
{
	if (fd == STDOUT_FILENO)
		putbuf(buffer, size);
	return size;
}

int open(const char *file)
{
	check_address(file);
}