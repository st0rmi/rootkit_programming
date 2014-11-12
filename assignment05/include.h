#ifndef INCLUDE_HEADER
#define INCLUDE_HEADER

#include <linux/types.h>

/* dirent structure */
struct linux_dirent {   
        unsigned long   d_ino;   
        unsigned long   d_off;   
        unsigned short  d_reclen;   
        char            d_name[1];   
};

void disable_page_protection (void);

void enable_page_protection (void);

ssize_t get_path(unsigned int fd, char *path, size_t bufsiz);

#endif
