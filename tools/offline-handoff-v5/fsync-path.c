#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
/* Flush only each named regular file or directory, never syncfs(). */
int main(int argc, char **argv) {
    if (argc < 2) return 64;
    for (int i=1;i<argc;i++) {
        int fd=open(argv[i],O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
        if(fd<0){perror(argv[i]);return 1;}
        struct stat st;
        if(fstat(fd,&st)||(!S_ISREG(st.st_mode)&&!S_ISDIR(st.st_mode))){close(fd);return 1;}
        if(fsync(fd)){perror(argv[i]);close(fd);return 1;}
        if(close(fd)){perror(argv[i]);return 1;}
    }
    return 0;
}
