#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <ctype.h>
#include <unistd.h>

#define BUFFERLENGTH 255

char *serverHost;
int serverPort;
char *operation;

int sockfd, n;

int addRule(char *ipAddress, char* port, char buffer[])
{
    bzero (buffer, BUFFERLENGTH);

    char message[256] = "0";
    strcat(message, ipAddress);
    strcat(message, " ");
    strcat(message, port);


    /* send message */
    n = write (sockfd, message, strlen(message));
    if (n < 0) 
    {
        perror ("ERROR writing to socket");
        exit(-1);
    }

    bzero (buffer, BUFFERLENGTH);

    /* wait for reply */
    n = read (sockfd, buffer, BUFFERLENGTH -1);
    if (n < 0) 
    {
        perror ("ERROR reading from socket");
        exit(-1);
    }

    printf ("%s\n",buffer);
    close(sockfd);

    return 0;
}

int checkRule(char *ipAddress, char *port, char buffer[])
{
    bzero(buffer, BUFFERLENGTH);
    char message[256] = "1";

    strcat(message, ipAddress);
    strcat(message, " ");
    strcat(message, port);

    /* send message */
    n = write (sockfd, message, strlen(message));
    if (n < 0) 
    {
        perror ("ERROR writing to socket");
        exit(-1);
    }

    bzero (buffer, BUFFERLENGTH);

    /* wait for reply */
    n = read (sockfd, buffer, BUFFERLENGTH -1);
    if (n < 0) 
    {
        perror ("ERROR reading from socket");
        exit(-1);
    }

    printf("%s\n",buffer);

    close(sockfd);

    return 0;
}

int deleteRule(char *ipAddress, char *port, char buffer[])
{
    bzero (buffer, BUFFERLENGTH);

    char message[256] = "2";
    strcat(message, ipAddress);
    strcat(message, " ");
    strcat(message, port);


    /* send message */
    n = write (sockfd, message, strlen(message));
    if (n < 0) 
    {
        perror ("ERROR writing to socket");
        exit(-1);
    }

    bzero (buffer, BUFFERLENGTH);

    /* wait for reply */
    n = read (sockfd, buffer, BUFFERLENGTH -1);
    if (n < 0) 
    {
        perror ("ERROR reading from socket");
        exit(-1);
    }

    printf ("%s\n",buffer);
    close(sockfd);

    return 0;
}

int showRules(char buffer[])
{
    bzero(buffer, BUFFERLENGTH);

    n = write(sockfd, "3", 2);
    if (n < 0) 
    {
        perror ("ERROR writing to socket");
        exit(-1);
    }

    bzero (buffer, BUFFERLENGTH);

    /* wait for reply */
    n = read (sockfd, buffer, BUFFERLENGTH -1);
    if (n < 0) 
    {
        perror ("ERROR reading from socket");
        exit(-1);
    }

    printf ("%s\n",buffer);
    close(sockfd);

    return 0;
}

int opToInt(char *operation)
{
    if(strcmp(operation, "A") == 0 || strcmp(operation, "a") == 0)
    {
        return 1;
    }

    if(strcmp(operation, "C") == 0 || strcmp(operation, "c") == 0)
    {
        return 2;
    }

    if(strcmp(operation, "D") == 0 || strcmp(operation, "d") == 0)
    {
        return 3;
    }

    if(strcmp(operation, "L") == 0 || strcmp(operation, "l") == 0)
    {
        return 4;
    }

    return -1;
}

int main (int argc, char **argv) {

    serverHost = argv[1];
    serverPort = atoi(argv[2]);
    operation = argv[3];

    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int res;
    

    char buffer[BUFFERLENGTH];
    if (argc < 3) 
    {
       fprintf (stderr, "usage %s hostname port\n", argv[0]);
       exit(1);
    }

    int intOperation = opToInt(operation);
    if(intOperation == -1)
    {
        printf("Invalid request");
        return -1;
    }

    /* Obtain address(es) matching host/port */
   /* code taken from the manual page for getaddrinfo */
    
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM; /* Datagram socket */
    hints.ai_flags = 0;
    hints.ai_protocol = 0;          /* Any protocol */

    res = getaddrinfo(argv[1], argv[2], &hints, &result);
    if (res != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(res));
        exit(EXIT_FAILURE);
    }

    /* getaddrinfo() returns a list of address structures.
       Try each address until we successfully connect(2).
       If socket(2) (or connect(2)) fails, we (close the socket
       and) try the next address. */
    
    for (rp = result; rp != NULL; rp = rp->ai_next) 
    {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd == -1)
            continue;

        if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) != -1)
            break;                  /* Success */

        close(sockfd);
    }

    if (rp == NULL) 
    {               /* No address succeeded */
	    fprintf(stderr, "Could not connect\n");
	    exit(EXIT_FAILURE);
    }

    freeaddrinfo(result);           /* No longer needed */

    switch(intOperation)
    {
        case 1:
            addRule(argv[4], argv[5], buffer);
            break;

        case 2:
            checkRule(argv[4], argv[5], buffer);
            break;

        case 3:
            deleteRule(argv[4], argv[5], buffer);
            break;

        case 4:
            showRules(buffer);
            break;

        case -1:
            printf("Invalid operation");
            return -1;
    }
    return 0;
}
