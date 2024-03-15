#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "lib/kernel/list.h"
#include "filesys/file.h"
#include "threads/synch.h"
#include "devices/input.h"

static void syscall_handler (struct intr_frame *);

static int get_user (const uint8_t *uaddr);

static int get_user_bytes (void *uaddr, void *dst, size_t bytes);

void sys_halt(void);

int sys_write(int fd, const void* buffer, unsigned size);

tid_t sys_exec(const char* cmd_line);

bool sys_create(const char *file, unsigned initial_size);

bool sys_remove(const char *file);

int sys_open (const char *file);

void sys_close(int fd);

static struct file_d* obtener_file_d(int fd);

int sys_filesize (int fd);
/*
    Espera un proceso pid secundario y recupera el estado de salida del subproceso.
*/
int sys_wait(tid_t pid);

struct lock archivos;

void
syscall_init (void)
{
  lock_init(&archivos);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  int sys_code;
  ASSERT( sizeof(sys_code) == 4 );
  if (get_user_bytes(f->esp, &sys_code, sizeof(sys_code)) == -1) {
    if (lock_held_by_current_thread(&archivos)){
      lock_release (&archivos);
    }
    sys_exit(-1);
  }

  switch (sys_code)
  {
    case SYS_HALT:
      {
        sys_halt();
        break;
      }
    case SYS_EXIT:
      {
        int status;

        if(get_user_bytes(f->esp + 4, &status, sizeof(status)) == -1){
          if (lock_held_by_current_thread(&archivos)){
            lock_release (&archivos);
          }
          sys_exit(-1);
        };

        sys_exit(status);

        break;
      }
    case SYS_WRITE:
      {
        int fd;
        const void* buffer;
        unsigned size;

        if (get_user_bytes(f->esp + 4, &fd, sizeof(fd)) == -1) {
          if (lock_held_by_current_thread(&archivos)){
            lock_release (&archivos);
          }
          sys_exit(-1);
        }

        if (get_user_bytes(f->esp + 8, &buffer, sizeof(buffer)) == -1) {
          if (lock_held_by_current_thread(&archivos)){
            lock_release (&archivos);
          }
          sys_exit(-1);
        }

        if (get_user_bytes(f->esp + 12, &size, sizeof(size)) == -1) {
          if (lock_held_by_current_thread(&archivos)){
            lock_release (&archivos);
          }
          sys_exit(-1);
        }

        int retorno = sys_write(fd, buffer, size);
        f->eax = (uint32_t)retorno;
        break;
      }
}
}

void sys_exit(int status){
  printf("%s: exit(%d)\n", thread_current()->name, status);

  struct process_control_block *pcb = thread_current()->pcb;
  if(pcb != NULL){
    pcb->curr_finish = true;
    pcb->exit_code = status;
  }
  thread_exit();
}

static int get_user (const uint8_t *uaddr)
{
  if(((void*)uaddr < PHYS_BASE)){
    int result;
    asm ("movl $1f, %0; movzbl %1, %0; 1:"
        : "=&a" (result) : "m" (*uaddr));
    return result;
  } else {
    return -1;
  }
}

static int get_user_bytes (void *uaddr, void *dst, size_t bytes){
  int32_t valor;
  size_t i; 
  for( i = 0; i < bytes; i++){
    valor = get_user(uaddr + i); 
    if(valor == -1){
      return -1;
    } else {
      *(char*)(dst + i) = valor & 0xff; 
    }
  }
  return (int)bytes;
};

int sys_write(int fd, const void* buffer, unsigned size){
  if(get_user((const uint8_t*)buffer) == -1){
    if (lock_held_by_current_thread(&archivos)){
      lock_release (&archivos);
    }
    sys_exit(-1);
  }
  if(get_user((const uint8_t*)(buffer + size -1)) == -1){
    if (lock_held_by_current_thread(&archivos)){
      lock_release (&archivos);
    }
    sys_exit(-1);
  }
  lock_acquire(&archivos);
  int retorno = 0;
  if(fd == 1){
    putbuf(buffer, size);
    retorno = size;
  } else {
    struct file_d* file_d = obtener_file_d(fd);
    if(file_d && file_d->file){
      retorno = file_write(file_d->file, buffer, size);
    } else {
      retorno = -1;
    }
  }
  lock_release(&archivos);
  return retorno;
}

static struct file_d* obtener_file_d(int fd){

  struct thread *t = thread_current();

  ASSERT(t!=NULL);

  if(fd<3){
    return NULL;
  }

  struct list *file_d_list = &t->file_d_list;
  struct list_elem *e;
  if(!list_empty(file_d_list)){
    for (e = list_begin (file_d_list); e != list_end (file_d_list); e = list_next (e))
    {
      struct file_d *file_d = list_entry(e,struct file_d, elem);
      if(file_d->id == fd){
        return file_d;
      }
    }
  }

  return NULL;
}
