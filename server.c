#include <stdio.h>
#include <stdio.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <ctype.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>

#define BUFFERLENGTH 256

#define THREAD_IN_USE 0
#define THREAD_FINISHED 1
#define THREAD_AVAILABLE 2
#define THREADS_ALLOCATED 10

struct firewallRules_t *allRules = NULL, *tmp;

struct threadArgs_t {
    int newsockfd;
    int threadIndex;
};

int isExecuted = 0;
int returnValue = 0; /* not used; need something to keep compiler happy */
pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER; /* the lock used for processing */

/* this is only necessary for proper termination of threads - you should not need to access this part in your code */
struct threadInfo_t {
    pthread_t pthreadInfo;
    pthread_attr_t attributes;
    int status;
};

struct threadInfo_t *serverThreads = NULL;
int noOfThreads = 0;
pthread_rwlock_t threadLock =  PTHREAD_RWLOCK_INITIALIZER;
pthread_cond_t threadCond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t threadEndLock = PTHREAD_MUTEX_INITIALIZER;

struct queries_t
{
    struct query_t *query;
    struct queries_t *next;
};

struct firewallRule_t 
{
    int ipaddr1[4];
    int ipaddr2[4];
    int port1;
    int port2;
    struct queries_t *queries;
};

struct query_t
{
    int ipaddr[4];
    int port;
};

struct firewallRules_t 
{
    struct firewallRule_t *rule;
    struct firewallRules_t *next;
};



struct queries_t * addQuery(struct queries_t *queries, struct query_t *query)
{
    struct queries_t *newQuery;

    newQuery = malloc(sizeof(struct queries_t));
    newQuery->query = query;
    newQuery->next = queries;
    return newQuery;
}

struct firewallRules_t * addRule (struct firewallRules_t * rules, struct firewallRule_t *rule)
{
    struct firewallRules_t *newRule;

    newRule = malloc(sizeof(struct firewallRules_t));
    newRule->rule = rule;
    newRule->next = rules;
    return newRule;
}

int compareIPAddresses (int *ipaddr1, int *ipaddr2) 
{
    int i;
    for (i = 0; i < 4; i++) {
	if (ipaddr1[i] > ipaddr2[i]) 
    {
	    return 1;
	}
	else if (ipaddr1[i] < ipaddr2[i]) 
    {
	    return -1;
	}
    }
    return 0;
}


int compareRules (struct firewallRule_t *rule1, struct firewallRule_t *rule2) 
{

    if ((rule1->port1) < (rule2->port1)) 
    {
        return -1;
    }
    else if (rule1->port1 > rule2->port1) 
    {
        return 1;
    }
    else 
        return (compareIPAddresses (rule1->ipaddr1, rule2->ipaddr1));
}

void updateList(struct firewallRules_t * linkedList, struct firewallRule_t *oldRule, struct firewallRule_t *newRule)
{

    while(linkedList != NULL)
    {
        if(compareRules(linkedList->rule, oldRule) == 0)
        {
            *(linkedList->rule) = *newRule;
            return;
        }

        linkedList = linkedList->next;
    }
}


/* parses one IP address. Returns NULL if text does not start with a valid IP address, and a pointer  to the first character after the valid IP address otherwise */
char *parseIPaddress (int *ipaddr, char *text) 
{
    char *oldPos, *newPos;
    long int addr;
    int i;

    oldPos = text;
    for (i = 0; i < 4; i++) 
    {
        if (oldPos == NULL || *oldPos < '0' || *oldPos > '9') 
        {
            return NULL;
        }

        addr = strtol(oldPos, &newPos, 10);

        if (newPos == oldPos) 
        {
            return NULL;
        }

        if ((addr < 0)  || addr > 255) 
        {
            ipaddr[0] = -1;
            return NULL;
        }

        if (i < 3) 
        {
            if ((newPos == NULL) || (*newPos != '.')) 
            {
                ipaddr[0] = -1;
                return NULL;
            }

            else newPos++;
        }
        else if ((newPos == NULL) || ((*newPos != ' ') && (*newPos != '-'))) 
        {
            ipaddr[0] = -1;
            return NULL;
        }

        ipaddr[i] = addr;
        oldPos = newPos;
    }

    return newPos;
}

char *parsePort (int *port, char *text) 
{
    char *newPos;

    
    if ((text == NULL) || (*text < '0') || (*text > '9')) 
    {
        return NULL;
    }

    *port = strtol(text, &newPos, 10);

    if (newPos == text) 
    {
        *port = -1;
        return NULL;
    }

    if ((*port < 0) || (*port > 65535)) 
    {
        *port = -1;
        return NULL;
    }

    return newPos;
}

struct firewallRule_t *readRule (char * line) 
{
    struct firewallRule_t *newRule;
    char *pos;

    // parse IP addresses 
    newRule = malloc (sizeof(struct firewallRule_t));
    pos = parseIPaddress (newRule->ipaddr1, line);
    if ((pos == NULL) || (newRule->ipaddr1[0] == -1)) {
        free (newRule);
        return NULL;
    }

    if (*pos == '-') {
        // read second IP address
        pos = parseIPaddress (newRule->ipaddr2, pos+1);
        if ((pos == NULL) || (newRule->ipaddr2[0] == -1)) {
            free (newRule);
            return NULL;
        }
    
        if (compareIPAddresses (newRule->ipaddr1, newRule->ipaddr2) != -1) {
            free(newRule);
            return NULL;
        }
    }
    else {
	    newRule->ipaddr2[0] = -1;
    }

    if (*pos != ' ') {
        free(newRule);
        return NULL;
    }
    else pos++;

    // parse ports
    pos = parsePort (&(newRule->port1), pos);
    if ((pos == NULL) || (newRule->port1 == -1)) {
        free(newRule);
        return NULL;
    }

    if ((*pos == '\n') || (*pos == '\0')) {
        newRule->port2 = -1;
        return newRule;
    }

    if (*pos != '-') {
        free(newRule);
        return NULL;
    }
    
    pos++;
    pos = parsePort (&(newRule->port2), pos);
    if ((pos == NULL) || (newRule->port2 == -1)) {
        free(newRule);
        return NULL;
    }

    if (newRule->port2 <= newRule->port1) {
        free(newRule);
        return NULL;
    }

    if ((*pos == '\n') || (*pos == '\0')) {
	    return newRule;
    }

    free(newRule);
    return NULL;
}

int deleteRule (struct firewallRules_t * rules, struct firewallRule_t *rule)
{

    if(rules == NULL) /* List is empty */
        return -1;

    if(compareRules(rules->rule, rule) == 0) /* Rule is first element in linked list */
    {
        struct firewallRules_t *tmp = rules;
        if(rules->rule->queries != NULL)
        {
            free(rules->rule->queries);
        }
        rules = rules->next;
        free(tmp);
        return 1;
    }

    if(rules->next == NULL) /* Rule not in list */
        return -1;

    if(compareRules(rules->next->rule, rule) == 0) /* If next rule == rule */
    {
        struct firewallRules_t *tmp = rules->next;
        if(rules->rule->queries != NULL)
        {
            free(rules->rule->queries);
        }
        rules->next = rules->next->next; /* Set next rule to the next rules next rule *, 1->next = 3 */
        free(tmp);
        return 1;
    }

    return deleteRule(rules->next, rule);

}

bool checkIPAddress (int *ipaddr1, int *ipaddr2, int *ipaddr) {
    int res;
    
    res =  compareIPAddresses (ipaddr, ipaddr1);
    if (compareIPAddresses (ipaddr, ipaddr1) == 0) {
	    return true;
    }

    if (ipaddr2[0] == -1) {
	    return false;
    }
    else if (res  == -1) {
	    return false;
    }
    else if (compareIPAddresses (ipaddr, ipaddr2) <= 0) {
	return true;
    }
    else {
	return false;
    }
}

int checkPort (int port1, int port2, int port) {
    if (port == port1) {
	return 0;
    }
    else if (port < port1) {
	return -1;
    }
    else if (port2 == -1 || port > port2) {
	return 1;
    }
    else {
	return 0;
    }
}

void parseQuery(struct query_t *query, char *buffer)
{
    /* Concatenate ipaddr */
    int i;
    char *tmp = (char *) malloc(6);

    for(i = 0; i < 3; i++)
    {
        sprintf(tmp, "%d", query->ipaddr[i]);
        strcat(buffer, tmp);
        strcat(buffer, ".");
    }

    sprintf(tmp, "%d", query->ipaddr[3]);
    strcat(buffer, tmp);

    strcat(buffer, " ");

    /* Concatenate port */

    sprintf(tmp, "%d", query->port);
    strcat(buffer, tmp);

    free(tmp);
    
}

void parseRule(struct firewallRule_t* rule, char *buffer)
{
    int i;
    char * tmp = (char *) malloc(4);

    for(i = 0; i < 3; i++)
    {
        sprintf(tmp, "%d", rule->ipaddr1[i]);
        strcat(buffer, tmp);
        strcat(buffer, ".");
    }

    sprintf(tmp, "%d", rule->ipaddr1[3]);
    strcat(buffer, tmp);

    if(rule->ipaddr2[0] != -1) /* Rule has range of ip */
    {
        /* Add second ip */
        strcat(buffer, "-");

        for(i = 0; i < 3; i++)
        {
            sprintf(tmp, "%d", rule->ipaddr2[i]);
            strcat(buffer, tmp);
            strcat(buffer, ".");
        }

        sprintf(tmp, "%d", rule->ipaddr2[3]);
        strcat(buffer, tmp);
    }

    strcat(buffer, " ");

    /* Ports */

    sprintf(tmp, "%d", rule->port1);
    strcat(buffer, tmp);

    if(rule->port2 != -1) /* Two ports */
    {
        strcat(buffer, "-");

        sprintf(tmp, "%d", rule->port2);
        strcat(buffer, tmp);
    }

    free(tmp);

    //return parsedRule;
}

/* For each connection, this function is called in a separate thread */
void *processRequest (void *args) 
{
    struct threadArgs_t *threadArgs;
    char buffer[BUFFERLENGTH];
    int n;

    threadArgs = (struct threadArgs_t *) args;
    bzero (buffer, BUFFERLENGTH);
    n = read (threadArgs->newsockfd, buffer, BUFFERLENGTH -1);
    if (n < 0) 
    {
        perror("ERROR reading from socket");
        exit(-1);
    }

    int operation;
    char *message;

    pthread_mutex_lock (&mut); /* lock exclusive access to variable isExecuted */

    operation = buffer[0] - '0';
    message = &buffer[1];

    struct firewallRule_t *newRule;

    switch(operation)
    {
        case 0: /* Add rule to list if valid */

            if((newRule = readRule(message)) == NULL) /* If rule is invalid */
            {
                n = sprintf (buffer, "Invalid rule");
                break;
            }

            /* Check if rule is alrewady in list */
            struct firewallRules_t *tmp = allRules;
            bool ruleFound = false;
            while(tmp && !ruleFound)
            {
                if(compareRules(tmp->rule, newRule) == 0)
                {
                    ruleFound = true;
                }

                tmp = tmp->next;
            }

            if(ruleFound)
            {
                n = sprintf(buffer, "Rule already in list");
                break;
            }

            /* Rule is valid */

            allRules = addRule(allRules, newRule);
            n = sprintf (buffer, "Rule added");

            break;

        case 1: 
        { 
         /* Check Rule */
             
            int res;
            if((newRule = readRule(message)) == NULL) /* If ip or port is invalid */
            {
                n = sprintf (buffer, "Illegal IP address or port specified");
                break;
            }

            struct query_t *query;
            query = malloc(sizeof(struct query_t));

            int i;
            for(i = 0; i < 4; i++)
            {
                query->ipaddr[i] = newRule->ipaddr1[i];
            }

            query->port = newRule->port1;

            struct firewallRule_t *rule;
            bool packetAccepted = false;

            tmp = allRules;
            while(tmp != NULL && !packetAccepted) 
            {
                res = checkPort (tmp->rule->port1, tmp->rule->port2, query->port);
                if (res < 0 || res > 0) 
                {
                    tmp = tmp->next;
                    continue;
                }

                if (res == 0) 
                {
                    packetAccepted = checkIPAddress (tmp->rule->ipaddr1, tmp->rule->ipaddr2, query->ipaddr);
                    rule = tmp->rule;
                    tmp = tmp->next;
                }

            }

            if(packetAccepted) /* Connection accepted */
            {
                n = sprintf(buffer, "Connection accepted");
                struct firewallRule_t *tmpRule = rule;
                tmpRule->queries = addQuery(rule->queries, query);
                updateList(allRules, rule, tmpRule);
                break;
            }

            n = sprintf(buffer, "Connection rejected");
            break;

        }

        case 2: /* Delete Rule */
            
            if((newRule = readRule(message)) == NULL) /* If rule is invalid */
            {
                n = sprintf(buffer, "Rule invalid");
                break;
            }

            /* Rule is valid */
            int num = deleteRule(allRules, newRule);

            if(num == 1)
            {
                n = sprintf(buffer, "Rule deleted");
                break;
            }

            /* Rule not in list */
            n = sprintf(buffer, "Rule not found");
            break;

        case 3: {
            struct firewallRules_t *tmp = allRules;

            if(tmp == NULL) /* No rules stored */
            {
                n = sprintf(buffer, "No rules stored");
                n = write (threadArgs->newsockfd, buffer, BUFFERLENGTH);
                if (n < 0) 
                {
                    perror ("ERROR writing to socket");
                    exit(-1);
                }

                break;
            }

            bzero(buffer, BUFFERLENGTH);

            struct queries_t *temp;
            temp = malloc(sizeof(struct queries_t));

            do
            {
                strcat(buffer, "Rule: ");
                parseRule(tmp->rule, (char *) buffer);
                strcat(buffer, "\n"); /* Add new line */

                temp = tmp->rule->queries;
                
                if(temp != NULL)
                {
                    while(temp->query != NULL) /* While rule has unadded queries */
                    {
                        strcat(buffer, "Query: ");
                        parseQuery(temp->query, (char *) buffer);
                        strcat(buffer, "\n");

                        if(temp->next == NULL)
                            break;

                        temp = temp->next;
                    }             
                }

                tmp = tmp->next;


            } while (tmp != NULL);

            n = write (threadArgs->newsockfd, buffer, strlen(buffer));
            if (n < 0) 
            {
                perror ("ERROR writing to socket");
                exit(-1);
            }

            bzero(buffer, BUFFERLENGTH);
            n = sprintf(buffer, "-1");
            
            break;

        }

        default:
            n = sprintf(buffer, "Illegal request");
            close (threadArgs -> newsockfd); /* important to avoid memory leak */
            break;
    }


    isExecuted++;
    pthread_mutex_unlock (&mut); /* release the lock */
    if(operation != 3)
    {
        /* send the reply back */
        n = write (threadArgs->newsockfd, buffer, BUFFERLENGTH);
        if (n < 0) 
        {
            perror ("ERROR writing to socket");
            exit(-1);
        }
    }
       
    /* these two lines are required for proper thread termination */
    serverThreads[threadArgs->threadIndex].status = THREAD_FINISHED;
    pthread_cond_signal(&threadCond);

    close (threadArgs->newsockfd); /* important to avoid memory leak */  
    free (threadArgs);
    pthread_exit (&returnValue);
}

/* Finds unused thread info slot; allocates more slots if necessary */
/* Ocdnly called by main thread */

int findThreadIndex () 
{
    int i, tmp;

    for (i = 0; i < noOfThreads; i++) 
    {
        if (serverThreads[i].status == THREAD_AVAILABLE)
        {
            serverThreads[i].status = THREAD_IN_USE;
            return i;
        }
    }

    /* no available thread found; need to allocate more threads */
    pthread_rwlock_wrlock (&threadLock);
    serverThreads = realloc(serverThreads, ((noOfThreads + THREADS_ALLOCATED) * sizeof(struct threadInfo_t)));
    noOfThreads = noOfThreads + THREADS_ALLOCATED;
    pthread_rwlock_unlock (&threadLock);

    if (serverThreads == NULL) {
    	fprintf (stderr, "Memory allocation failed\n");
	    exit (1);
    }
    /* initialise thread status */
    for (tmp = i+1; tmp < noOfThreads; tmp++) {
	serverThreads[tmp].status = THREAD_AVAILABLE;
    }
    serverThreads[i].status = THREAD_IN_USE;
    return i;
}

/* waits for threads to finish and releases resources used by the thread management functions. You don't need to modify this function */
void *waitForThreads(void *args) 
{
    int i, res;
    while (1) {
	pthread_mutex_lock(&threadEndLock);
	pthread_cond_wait(&threadCond, &threadEndLock);
	pthread_mutex_unlock(&threadEndLock);

	pthread_rwlock_rdlock(&threadLock);
	for (i = 0; i < noOfThreads; i++) {
	    if (serverThreads[i].status == THREAD_FINISHED) 
        {
            res = pthread_join (serverThreads[i].pthreadInfo, NULL);
            if (res != 0) {
                fprintf (stderr, "Thread joining failed, exiting\n");
                exit (1);
            }

            serverThreads[i].status = THREAD_AVAILABLE;
	    }
	}

	pthread_rwlock_unlock(&threadLock);
    }
}

int main (int argc, char **argv) 
{
    socklen_t clilen;
    int sockfd, portno;
    struct sockaddr_in6 serv_addr, cli_addr;
    int result;
    pthread_t waitInfo;
    pthread_attr_t waitAttributes;

    if (argc < 2) {
        fprintf (stderr,"ERROR, no port provided\n");
        exit(1);
    }
    
    /* create socket */
    sockfd = socket (AF_INET6, SOCK_STREAM, 0);
    if (sockfd < 0) 
    {
        perror("ERROR opening socket");
        exit(-1);
    }
    
    bzero ((char *) &serv_addr, sizeof(serv_addr));

    portno = atoi(argv[1]);
    serv_addr.sin6_family = AF_INET6;
    serv_addr.sin6_addr = in6addr_any;
    serv_addr.sin6_port = htons (portno);

    /* bind it */
    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) 
    {
        perror("ERROR on binding");
        exit(-1);
    }

     /* ready to accept connections */
    listen (sockfd,5);
    clilen = sizeof (cli_addr);
    
    /* create separate thread for waiting  for other threads to finish */
    if (pthread_attr_init (&waitAttributes)) {
        fprintf (stderr, "Creating initial thread attributes failed!\n");
        exit (1);
    }

    result = pthread_create (&waitInfo, &waitAttributes, waitForThreads, NULL);
    if (result != 0) 
    {
        fprintf (stderr, "Initial Thread creation failed!\n");
        exit (1);
    }

    //int operation;
    //char *message;

    /* now wait in an endless loop for connections and process them */
    while(1) {
       
        struct threadArgs_t *threadArgs; /* must be allocated on the heap to prevent variable going out of scope */
        int threadIndex;

        threadArgs = malloc(sizeof(struct threadArgs_t));
        if (!threadArgs) {
            fprintf (stderr, "Memory allocation failed!\n");
            exit (1);
        }

        /* waiting for connections */
        threadArgs->newsockfd = accept( sockfd, (struct sockaddr *) &cli_addr,&clilen);
        if (threadArgs->newsockfd < 0) 
        {
            perror ("ERROR on accept");
            exit(-1);
        }

        /* create thread for processing of connection */
        threadIndex = findThreadIndex();
        threadArgs->threadIndex = threadIndex;
        if (pthread_attr_init (&(serverThreads[threadIndex].attributes))) 
        {
            fprintf (stderr, "Creating thread attributes failed!\n");
            exit (1);
        }
        
        
        result = pthread_create (&(serverThreads[threadIndex].pthreadInfo), &(serverThreads[threadIndex].attributes), processRequest, (void *) threadArgs);
        if (result != 0) 
        {
            fprintf (stderr, "Thread creation failed!\n");
            exit (1);
        }
    
    }

     return 0; 
}