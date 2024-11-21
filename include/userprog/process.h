#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H
#define STDIN 1 
#define STDOUT 2
#define STDERR 3


#include "threads/thread.h"

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);


int process_add_file(struct file *f);
struct file *process_get_file(int fd);
int process_close_file(int fd); 
struct thread *getc_child_process(int pid);


#endif /* userprog/process.h */
