#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"

/* elemento de file_d_list */
struct file_d {
  int id;
  struct list_elem elem;
  struct file* file;
};

struct process_control_block {
  tid_t pid;
  const char* cmdline;
  struct list_elem elem;
  bool parent_wait;
  bool curr_finish;
  int exit_code;
  struct semaphore inicio;
  struct semaphore tiempo_padre;
  bool libera_hijo;
};

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
