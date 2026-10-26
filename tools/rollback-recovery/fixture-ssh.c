#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
int main(void) {
    int fd=socket(AF_INET,SOCK_STREAM,0), yes=1;
    setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof yes);
    struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons(18180),.sin_addr.s_addr=htonl(INADDR_ANY)};
    if(bind(fd,(void*)&a,sizeof a)||listen(fd,8))return 2;
    FILE *f=fopen("/fixture/starts","a"); if(!f)return 3;
    fprintf(f,"%d\n",getpid());fclose(f);
    f=fopen("/fixture/childpid","w");if(!f)return 4;
    fprintf(f,"%d\n",getpid());fclose(f);
    for(;;){int c=accept(fd,0,0);if(c<0)return 5;write(c,"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n",38);close(c);}
}
