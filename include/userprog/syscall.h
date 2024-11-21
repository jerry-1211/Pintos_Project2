#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
void halt(void);
void exit(int status);
int dup2(int oldfd, int newfd);
process_insert_file(int fd, struct file *f);


#endif /* userprog/syscall.h */
