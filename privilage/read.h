#ifndef READ_HEADER
#define READ_HEADER

//#include "include.h"

asmlinkage long manipulated_read (unsigned int fd, char __user *buf, size_t count);

#endif
