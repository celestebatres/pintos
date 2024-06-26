#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "filesys/file.h"
#include "devices/input.h"
#include "lib/kernel/list.h"
#include "threads/synch.h"

typedef int mapid_t;

static void syscall_handler(struct intr_frame *);

static int get_user(const uint8_t *uaddr);

static int get_user_bytes(void *uaddr, void *dst, size_t bytes);

void sys_halt(void);

int sys_write(int fd, const void *buffer, unsigned size);

tid_t sys_exec(const char *cmd_line);

bool sys_create(const char *file, unsigned initial_size);

bool sys_remove(const char *file);

int sys_open(const char *file);

void sys_close(int fd);

static struct file_d *obtener_file_d(int fd);

int sys_filesize(int fd);

/*Esperamos la finalizacion del child_process y retorna su estado de salida*/
int sys_wait(tid_t pid);

struct lock archivos;

static bool put_user(uint8_t *udst, uint8_t byte);

void sys_seek(int fd, unsigned position);

unsigned sys_tell(int fd);

static mapid_t mmap (int, void *);

static void  sys_munmap (mapid_t mapid);

void syscall_init(void)
{
  lock_init(&archivos);
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}


static mapid_t allocate_mapid (void);

static void
syscall_handler(struct intr_frame *f UNUSED)
{
  int sys_code;
  ASSERT(sizeof(sys_code) == 4);
  if (get_user_bytes(f->esp, &sys_code, sizeof(sys_code)) == -1)
  {
    if (lock_held_by_current_thread(&archivos))
    {
      lock_release(&archivos);
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

      if (get_user_bytes(f->esp + 4, &status, sizeof(status)) == -1)
      {
        if (lock_held_by_current_thread(&archivos))
        {
          lock_release(&archivos);
        }
        sys_exit(-1);
      };

      sys_exit(status);

      break;
    }
    case SYS_WRITE:
    {
      int fd;
      const void *buffer;
      unsigned size;

      if (get_user_bytes(f->esp + 4, &fd, sizeof(fd)) == -1)
      {
        if (lock_held_by_current_thread(&archivos))
        {
          lock_release(&archivos);
        }
        sys_exit(-1);
      }

      if (get_user_bytes(f->esp + 8, &buffer, sizeof(buffer)) == -1)
      {
        if (lock_held_by_current_thread(&archivos))
        {
          lock_release(&archivos);
        }
        sys_exit(-1);
      }

      if (get_user_bytes(f->esp + 12, &size, sizeof(size)) == -1)
      {
        if (lock_held_by_current_thread(&archivos))
        {
          lock_release(&archivos);
        }
        sys_exit(-1);
      }

      int retorno = sys_write(fd, buffer, size);
      f->eax = (uint32_t)retorno;
      break;
    }
    case SYS_REMOVE:
    {
      const char *filename;
      if (get_user_bytes(f->esp + 4, &filename, sizeof(filename)) == -1)
      {
        if (lock_held_by_current_thread(&archivos))
        {
          lock_release(&archivos);
        }
        sys_exit(-1);
      }
      bool retorno = sys_remove(filename);
      f->eax = retorno;
      break;
    }
    case SYS_CREATE:
    {
      const char *filename;
      unsigned initial_size;

      if (get_user_bytes(f->esp + 4, &filename, sizeof(filename)) == -1)
      {
        if (lock_held_by_current_thread(&archivos))
        {
          lock_release(&archivos);
        }
        sys_exit(-1);
      }

      if (get_user_bytes(f->esp + 8, &initial_size, sizeof(initial_size)) == -1)
      {
        if (lock_held_by_current_thread(&archivos))
        {
          lock_release(&archivos);
        }
        sys_exit(-1);
      }

      bool retorno = sys_create(filename, initial_size);
      f->eax = retorno;

      break;
    }
    case SYS_EXEC:
    {
      void *cmd_line;

      int retorno = get_user_bytes(f->esp + 4, &cmd_line, sizeof(cmd_line));
      if (retorno == -1)
      {
        if (lock_held_by_current_thread(&archivos))
        {
          lock_release(&archivos);
        }
        sys_exit(-1);
      }

      retorno = sys_exec((const char *)cmd_line);
      f->eax = (uint32_t)retorno;
      break;
    }
    case SYS_READ:
    {
      int fd;
      void* buffer;
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

      int retorno = sys_read(fd, buffer, size);
      f->eax = (uint32_t)retorno;
      break;
    }
    case SYS_WAIT:
    {
      tid_t pid;
      if (get_user_bytes(f->esp + 4, &pid, sizeof(tid_t)) == -1){
        if (lock_held_by_current_thread(&archivos)){
          lock_release (&archivos);
        }
        sys_exit(-1);
      }

      int retorno = sys_wait(pid);
      f->eax = retorno;
      break;
    }
    case SYS_OPEN:
    {
      const char* filename;

      if (get_user_bytes(f->esp + 4, &filename, sizeof(filename)) == -1) {
        if (lock_held_by_current_thread(&archivos)){
          lock_release (&archivos);
        }
        sys_exit(-1);
      }

      int retorno = sys_open(filename);
      f->eax = retorno;
      break;
    }
    case SYS_CLOSE:
    {
      int fd;
      if (get_user_bytes(f->esp + 4, &fd, sizeof(fd)) == -1) {
        if (lock_held_by_current_thread(&archivos)){
          lock_release (&archivos);
        }
        sys_exit(-1);
      }
      sys_close(fd);
      break;
    }
    case SYS_FILESIZE:
    {
      int fd;
      if (get_user_bytes(f->esp + 4, &fd, sizeof(fd)) == -1) {
        if (lock_held_by_current_thread(&archivos)){
          lock_release (&archivos);
        }
        sys_exit(-1);
      }

      int retorno = sys_filesize(fd);
      f->eax = retorno;
      break;
    }
    case SYS_SEEK:
    {
      int fd;
      unsigned position;

      if (get_user_bytes(f->esp + 4, &fd, sizeof(fd)) == -1) {
        if (lock_held_by_current_thread(&archivos)){
          lock_release (&archivos);
        }
        sys_exit(-1);
      }

      if (get_user_bytes(f->esp + 8, &position, sizeof(position)) == -1) {
        if (lock_held_by_current_thread(&archivos)){
          lock_release (&archivos);
        }
        sys_exit(-1);
      }

      sys_seek(fd, position);
      break;
    }
    case SYS_TELL:
    {
      int fd;

      if (get_user_bytes(f->esp + 4, &fd, sizeof(fd)) == -1) {
        if (lock_held_by_current_thread(&archivos)){
          lock_release (&archivos);
        }
        sys_exit(-1);
      }

      unsigned retorno = sys_tell(fd);
      f->eax = (uint32_t)retorno;
      break;
    }
    case SYS_MMAP:
    {
      int fd;
      void *addr;

      if (get_user_bytes(f->esp + 4, &fd, sizeof(fd)) == -1) {
        if (lock_held_by_current_thread(&archivos)){
          lock_release (&archivos);
        }
        sys_exit(-1);
      }

      int retorno = sys_filesize(fd);
      f->eax = mmap (fd, addr);
      break;
    }
    /*case SYS_MUNMAP:
    {
      mapid_t mid;
      memread_user(f->esp + 4, &mid, sizeof(mid));

      sys_munmap(mid);
    }*/
    default:
      printf("[ERROR] system call %d is unimplemented!\n", sys_code);
      sys_exit(-1);
      break;
  }
}

void sys_exit(int status)
{
  printf("%s: exit(%d)\n", thread_current()->name, status);

  struct process_control_block *pcb = thread_current()->pcb;
  if (pcb != NULL)
  {
    pcb->curr_finish = true;
    pcb->exit_code = status;
  }
  thread_exit();
}

static int get_user(const uint8_t *uaddr)
{
  if (((void *)uaddr < PHYS_BASE))
  {
    int result;
    asm("movl $1f, %0; movzbl %1, %0; 1:"
        : "=&a"(result) : "m"(*uaddr));
    return result;
  }
  else
  {
    return -1;
  }
}

static bool put_user(uint8_t *udst, uint8_t byte)
{
  if (((void *)udst < PHYS_BASE))
  {
    int error_code;
    asm("movl $1f, %0; movb %b2, %1; 1:"
        : "=&a"(error_code), "=m"(*udst) : "q"(byte));
    return error_code != -1;
  }
  else
  {
    return false;
  }
}

static int get_user_bytes(void *uaddr, void *dst, size_t bytes)
{
  int32_t valor;
  size_t i;
  for (i = 0; i < bytes; i++)
  {
    valor = get_user(uaddr + i);
    if (valor == -1)
    {
      return -1;
    }
    else
    {
      *(char *)(dst + i) = valor & 0xff;
    }
  }
  return (int)bytes;
};

void sys_halt(void)
{
  shutdown_power_off();
}

int sys_write(int fd, const void *buffer, unsigned size)
{
  if (get_user((const uint8_t *)buffer) == -1)
  {
    if (lock_held_by_current_thread(&archivos))
    {
      lock_release(&archivos);
    }
    sys_exit(-1);
  }
  if (get_user((const uint8_t *)(buffer + size - 1)) == -1)
  {
    if (lock_held_by_current_thread(&archivos))
    {
      lock_release(&archivos);
    }
    sys_exit(-1);
  }
  lock_acquire(&archivos);
  int retorno = 0;
  if (fd == 1)
  {
    putbuf(buffer, size);
    retorno = size;
  }
  else
  {
    struct file_d *file_d = obtener_file_d(fd);
    if (file_d && file_d->file)
    {
      retorno = file_write(file_d->file, buffer, size);
    }
    else
    {
      retorno = -1;
    }
  }
  lock_release(&archivos);
  return retorno;
}

static struct file_d *obtener_file_d(int fd)
{

  struct thread *t = thread_current();

  ASSERT(t != NULL);

  if (fd < 3)
  {
    return NULL;
  }

  struct list *file_d_list = &t->file_d_list;
  struct list_elem *e;
  if (!list_empty(file_d_list))
  {
    for (e = list_begin(file_d_list); e != list_end(file_d_list); e = list_next(e))
    {
      struct file_d *file_d = list_entry(e, struct file_d, elem);
      if (file_d->id == fd)
      {
        return file_d;
      }
    }
  }

  return NULL;
}

bool sys_remove(const char *file)
{
  if (get_user((const uint8_t *)file) == -1)
  {
    if (lock_held_by_current_thread(&archivos))
    {
      lock_release(&archivos);
    }
    sys_exit(-1);
  }
  lock_acquire(&archivos);
  bool retorno = filesys_remove(file);
  lock_release(&archivos);
  return retorno;
}

bool sys_create(const char *file, unsigned initial_size)
{
  if (get_user((const uint8_t *)file) == -1)
  {
    if (lock_held_by_current_thread(&archivos))
    {
      lock_release(&archivos);
    }
    sys_exit(-1);
  }
  lock_acquire(&archivos);
  bool retorno = filesys_create(file, initial_size);
  lock_release(&archivos);
  return retorno;
}

tid_t sys_exec(const char *cmd_line)
{
  if (get_user((const uint8_t *)cmd_line) == -1)
  {
    sys_exit(-1);
  }
  lock_acquire(&archivos);
  tid_t pid = process_execute(cmd_line);
  lock_release(&archivos);

  return pid;
}

int sys_read(int fd, void *buffer, unsigned size) {

  if (get_user((const uint8_t*) buffer) == -1) {
    if (lock_held_by_current_thread(&archivos)){
      lock_release (&archivos);
    }
    sys_exit(-1);
  }

  if (get_user((const uint8_t*) (buffer + size -1)) == -1) {
    if (lock_held_by_current_thread(&archivos)){
      lock_release (&archivos);
    }
    sys_exit(-1);
  }

  lock_acquire(&archivos);
  int retorno = 0;
  if(fd == 1){
    retorno -1;
  } else if(fd == 0) {
    uint8_t c;
    unsigned counter = size;
    uint8_t *buf = buffer;
    while (counter > 1 && (c = input_getc()) != 0)
      {
        *buf = c;
        buffer++;
        counter--;
      }
    *buf = 0;
    retorno = size - counter;
  } else {
    struct file_d* file_d = obtener_file_d(fd);

    if(file_d && file_d->file) {
      retorno = file_read(file_d->file, buffer, size);
    } else {
      retorno = -1;
    }
  }
  lock_release(&archivos);
  return retorno;
}

int sys_wait(tid_t pid){
  return process_wait(pid);
}

int sys_open(const char* file) {
  if (get_user((const uint8_t*)file) == -1) {
    if (lock_held_by_current_thread(&archivos)){
      lock_release (&archivos);
    }
    sys_exit(-1);
  }
  struct file* file_opened;
  struct file_d* fd = palloc_get_page(0);
  if(!fd){
    return -1;
  }

  lock_acquire(&archivos);
  file_opened = filesys_open(file);
  if (!file_opened) {
    palloc_free_page(fd);
    lock_release(&archivos);
    return -1;
  }

  fd->file = file_opened;
  struct list* file_d_list = &thread_current()->file_d_list;
  if (list_empty(file_d_list)) {
    fd->id = 3;
  } else {
    fd->id = (list_entry(list_back(file_d_list), struct file_d, elem)->id) + 1;
  }

  list_push_back(file_d_list, &(fd->elem));

  lock_release(&archivos);
  return fd->id;
}

void sys_close(int fd) {
  lock_acquire(&archivos);

  struct file_d* file_d = obtener_file_d(fd);

  if(file_d && file_d->file) {
    file_close(file_d->file);
    list_remove(&(file_d->elem));
    palloc_free_page(file_d);
  }
  lock_release(&archivos);
}

int sys_filesize(int fd) {
  struct file_d* file_d;

  if (get_user((const uint8_t*)fd) == -1) {
    if (lock_held_by_current_thread(&archivos)){
      lock_release (&archivos);
    }
    sys_exit(-1);
  }

  lock_acquire(&archivos);
  printf;

  file_d = obtener_file_d(fd);

  if(file_d == NULL) {
    lock_release(&archivos);
    return -1;
  }

  int retorno = file_length(file_d->file);

  lock_release(&archivos);

  return retorno;
}

void sys_seek (int fd, unsigned position){
  lock_acquire(&archivos);
  struct file_d *file_d = obtener_file_d(fd);

  if(file_d && file_d->file){
    file_seek(file_d->file, position);
  } else {
    return;
  }
  lock_release(&archivos);
}

unsigned sys_tell(int fd){
  lock_acquire(&archivos);
  struct file_d *file_d = obtener_file_d(fd);
  printf("Dirección del puntero al stack: %p\n", &file_d);
  int retorno;
  if(file_d && file_d->file) {
    retorno = file_tell(file_d->file);
  } else {
    retorno = -1;
  }
  lock_release(&archivos);
  return retorno;
}

mapid_t mmap(int fd, void *addr) {
    struct thread *t = thread_current();
    struct file_d *file_d = obtener_file_d(fd);

    if (addr == NULL || pg_ofs(addr) != 0 || fd == 0 || fd == 1 || fd == STDIN_FILENO || fd == STDOUT_FILENO || file_d == NULL)
        return -1;

    size_t file_size = file_length(file_d->file);
    if (file_size <= 0)
        return -1;

    lock_acquire(&archivos);
    struct file *file = file_reopen(file_d->file);
    lock_release(&archivos);
    if (file == NULL)
        return -1;

    size_t ofs = 0;
    while (file_size > 0) {
        size_t read_bytes = file_size < PGSIZE ? file_size : PGSIZE;
        size_t zero_bytes = PGSIZE - read_bytes;

        if (vm_find_page(addr) != NULL)
            return -1;

        vm_new_file_page(addr, file, ofs, read_bytes, zero_bytes, true, -1);

        ofs += PGSIZE;
        file_size -= read_bytes;
        addr += PGSIZE;
    }

    mapid_t map_id = allocate_mapid();
    if (map_id == -1) {
        file_close(file);
        return -1;
    }

    vm_insert_mfile(map_id, fd, addr - ofs, addr);

    return map_id;
}

void sys_munmap(mapid_t mid) {
    struct thread *t = thread_current();
    struct mmap_desc *mmap_d = find_mmap_desc(t, mid);

    if (mmap_d == NULL) { // No se encontró el descriptor de mmap
        return; // Terminar la ejecución sin hacer nada
    }

    lock_acquire(&archivos);
    {
        // Iterar sobre cada página y desmapearla
        size_t offset, file_size = mmap_d->size;
        for (offset = 0; offset < file_size; offset += PGSIZE) {
            void *addr = mmap_d->addr + offset;
            size_t bytes = (offset + PGSIZE < file_size ? PGSIZE : file_size - offset);
        }

        // Liberar recursos y eliminar de la lista
        list_remove(&mmap_d->elem);
        file_close(mmap_d->file);
        free(mmap_d);
    }
    lock_release(&archivos);
}


static mapid_t allocate_mapid (void)
{
  static mapid_t next_mapid = 0;
  return next_mapid++;
}
