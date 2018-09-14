
/**
   The relevant header files
**/
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>  
#include <arpa/inet.h>  
#include <netinet/tcp.h>
#include <netdb.h>
#include <unistd.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include "strutils.h"
#include "linkedlist.h"
#include "sys/stat.h"
#include <dirent.h>
#include <sys/types.h>
#include "urldecode.h"



#define first_html "HTTP/1.1 200 OK\r\n\r\n<html>\n\t<head><title>Leitourgika</title>\n<style>\nh1.dirlist { background-color: yellow; }\n\
</style>\n<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\">\
</head>\n<body>\n<h1 class=\"dirlist\">Directory listing: "


#define forma "\t<form method=\"POST\">\n\t\tFind pattern <input type=\"text\
\" name=\"pattern\" value=\"\" />\n\t\t<input type=\"submit\" value=\
\"Find\"/>\n\t\t<input type=\"reset\" value=\"Clear\"/>\n\t</form>\n\n"

#define second_html "\n\n</h1><table>\n<thead>\n\t<tr>\n\t\t<th>Name</th>\n\t\t<th>\
Type</th>\n\t\t<th>Size</th>\n\t</tr>\n</thead>\n<tbody>\n"
#define last_html "</tbody>\n</table>\n</body></html>"

#define RE400 "HTTP/1.1 400 Bad request\r\n\r\n<html>\n\t<head>\
	<title> Invalid Request </title></head>\n<body>\nThe HTTP request \
	that was recieved was not as expected.\n\t</thead>\n<tbody>\n"

/**
  Useful Preprocessor macros
**/

/* Report an error and abort */
#define FATAL_ERROR(message)						\
  {									\
    fprintf(stderr,"In %s(%d) [function %s]: %s\n",			\
	    __FILE__, __LINE__, __FUNCTION__ , (message)  );		\
    abort();								\
  }									\

/* Report a posix error (similar to perror) and abort */
#define FATAL_PERROR(errcode) FATAL_ERROR(strerror(errcode))

/* check return code of command and abort on error with suitable
   message */
#define CHECK_ERRNO(command) { if((command) == -1) FATAL_PERROR(errno); }

/* Return a copy of obj (an lvalue) in a newly malloc'd area. */
#define OBJDUP(obj) memcpy(Malloc(sizeof(obj)), &(obj), sizeof(obj))

/* Copy to obj from src, using sizeof(obj). Note that obj is an
   lvalue but src is a pointer! */
#define COPY(obj, src) (void)memcpy(&(obj), (src), sizeof(obj))

/* Allocate a new object of the given type */
#define NEW(type) ((type *) Malloc(sizeof(type)))

/**
   Error-checking replacements for library functions.
**/
/*
  Allocate n bytes and return the pointer to the allocated memory.
  This function is a wrapper for malloc. However, where malloc returns
  NULL on error (e.g. out of memory), this function will print a
  diagnostic and abort().
 */
void* Malloc(size_t n) 
{
  void* new = malloc(n);
  if(new==NULL) FATAL_ERROR("Out of memory.");
  return new;
}
/*
 This function calls close(fd), checking the return code.
  It repeats the call on EINTR, and returns any other errors to the
  user.

  It is a common but nevertheless serious programming error not to
  check the return code of close().
 */
int Close(int fd)
{
  int rc;
  do { rc=close(fd); } while(rc==EINTR);
  return rc;
}

/***
   Typedefs
***/

/* Type of function that can be ran in a new thread */
typedef void* (*thread_proc)(void *);

/**
   Code
**/

typedef struct tcpip_connection
{
  int connfd;			/* file descriptor of connection */
  struct sockaddr_in peer_addr;	/* peer address */
} tcpip_connection;

/* Type of function that handles connections in a new thread */
typedef void* (*connection_handler)(tcpip_connection*);


char* convert_to_html(char*);
char* find_Elements(char *,char *);
void receive_message(int);
char* find(char *,char *);

/*
  Translate a hostname and port into a list of socket addresses
  suitable for connection. The reason we are returning a list, instead
  of a single address, is that a host may have several interfaces,
  each with its own address. Usually, a list of size 1 will be returned.

  Parameters:
  hostname - the name of the server to connect to, e.g. "localhost"
  port     - the port to connect to
  qreply   - pointer to a variable of type addrinfo*, which will hold
             the head of the list.

  Return:
  0 for success, and make *qreply point to the list of replies.

  On failure, returns some error code, which can be passed to
  gai_strerror for turning into a readable message.
*/
int get_client_address(const char* hostname, 
		       unsigned short port, 
		       struct addrinfo** qreply)
{
  int rc;			/* return codes */
  struct addrinfo qhints;	/* query hints */
  char service[10];

  /* Prepare query hints */
  memset(&qhints, 0, sizeof(qhints));
  qhints.ai_family = AF_INET;
  qhints.ai_socktype = SOCK_STREAM;
  qhints.ai_flags = AI_NUMERICSERV;
  sprintf(service, "%hu", port);
  
  /* Try to translate the name to an address */
  rc = getaddrinfo(hostname, service, &qhints, qreply);
  
  return rc;
}

/* 
   Make a client connection to a server, given a list of candidate
   addresses. The list could have been obtained by a call to
   get_client_address.

   Parameters:
   addr - a pointer to the head of the list of addresses to try

   Return:
   A new connection object on success.
   NULL on error.

   Side effects:
   In any case, deallocate addr.
*/
tcpip_connection* client_connect(struct addrinfo* addr)
{
  tcpip_connection conn;
  struct addrinfo* a;


  /* Try all the addresses in the list */
  for(a = addr; a != NULL; a = a->ai_next) {
    
    /* Try to create the socket */
    conn.connfd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
    if(conn.connfd==-1) continue;  /* Failed */

    /* Try to connect the socket. */
    if( connect(conn.connfd, a->ai_addr, a->ai_addrlen) != -1 )
      break;  /* Success */
    else
      CHECK_ERRNO(Close(conn.connfd));
  }

  /* If a!=NULL, we were successful */
  if(a) {
    COPY(conn.peer_addr, a->ai_addr);
    freeaddrinfo(addr);
    return OBJDUP(conn);
  } else {
    freeaddrinfo(addr);
    return NULL;
  }
}

/*
  Create, configure and return the file descriptor for a listening

  tcp socket on the given port, on every interface of this host. 
  The returned file descriptor can be used by accept to create new TCP
  connections. 

  Parameters:
  listening_port - the port on which the returned socket will listen

  Return:
  A server socket, ready to be used by accept.

  Side effects:
  In case of error, the program will abort(), printing a diagnostic
  message. 
 */

int create_server_socket(int listening_port)
{
  int server_socket;	/* the file descriptor of the listening socket
			   */  
  struct sockaddr_in listening_address; /* the network address of the
					   listening socket */
  int rc;		/* used to call setsockopt */
  

  /* create the listening socket, as an INET (internet) socket with
     TCP (stream) data transfer */
  CHECK_ERRNO(server_socket=socket(AF_INET, SOCK_STREAM, 0));
  
  
  /* we need to set a socket option (Google for it, or ask in class) */
  rc = 1;
  CHECK_ERRNO(setsockopt(server_socket, 
			 SOL_SOCKET, SO_REUSEADDR, 
			 &rc, sizeof(int)));
  
  /* Prepare address for a call to bind.
   The specified address will be the INADDR_ANY address (meaning "every
   address on this machine" and the port.
  */
  memset(&listening_address, 0, sizeof(listening_address));
  listening_address.sin_family      = AF_INET;
  listening_address.sin_addr.s_addr = htonl(INADDR_ANY);
  listening_address.sin_port        = htons(listening_port);

  /* Bind listening socket to the listening address */
  CHECK_ERRNO(bind(server_socket, 
		   (struct sockaddr*) &listening_address, 
		   sizeof(listening_address)));

  /* Make server_socket a listening socket (aka server socket) */
  CHECK_ERRNO(listen(server_socket, 15));

  return server_socket;
}

/*
  Repeatedly accept connections on server_socket (a listening socket)
  and call the handler on each new connection. When server_socket is
  closed, exit. 

  Parameters:
  server_socket - the socket used by accept
  handler       - a pointer to the handler function to call for each
                  new connection.

  Returns:
  nothing
 */
void server(int server_socket, connection_handler handler) 
{
  int new_connection;	/* the file descriptor of new connections */
  struct sockaddr_in peer_address; /* The network address of a
				      connecting peer, as returned 
				      by accept */
  socklen_t peer_addrlen;	/* Length of peer_address */
  tcpip_connection conn;	/* Object to pass to handler */

  /* Now we can accept connections on server_socket */
  while(1) {

    /* accept a new connection */
    peer_addrlen = sizeof(peer_address);
    new_connection = accept(server_socket, 
			    (struct sockaddr*) &peer_address, 
			    &peer_addrlen);

    /* check return value */
    if(new_connection==-1) {
      if( errno==EINTR		   /* Call interrupted by signal */
	  || errno==ECONNABORTED   /* connection was aborted */
	  || errno==EMFILE	   /* per-process limit of open fds */
	  || errno==ENFILE	   /* system-wide limit of open fds */
	  || errno==ENOBUFS	   /* no space for socket buffers */
	  || errno==ENOMEM	   /* no space for socket buffers */
	  || errno==EPERM	   /* Firewall blocked the connection */
	  )
	continue; /* we failed with this connection, retry with the
		     next one! */
      
      if(errno == EBADF)
	break;			/* return, the server_socket is closed */

      /* on all other errors, abort */
      FATAL_PERROR(errno);
    }

    /* ok, we have a valid connection */
    assert(new_connection>=0);
    conn.connfd = new_connection;
    COPY(conn.peer_addr, &peer_address);

    /* call the handler */
    handler(&conn);
    
  } /* end while */

}

/**

   Main program.

   Here, we create a server thread, accepting connections.

   Then we invoke repeatedly a client routine which connects 
   to the server (in the same process!!), gets a message from 
   the server, prints it, and quits. 

   Once the clients have finished, we make the server quit as well,
   by closing the listening socket and sending a signal to the
   server thread.

   The purpose of this program is to exhibit some techiques that
   may be used in the class project.

 **/

/**
  Server functions.
**/

/*
  This function is called from server_handler to write a message
  to a socket.
*/
void write_message(int fd, const char* message)
{
  int pos, len,rc;
  
  pos = 0;
  len = strlen(message);
  while(pos!=len) {
  dowrite:
    rc = write(fd, message+pos, len-pos);
    if(rc<0) {
      /* ooh, an error has occurred */
      if(errno==EINTR) goto dowrite;

      /* Report the error and break */
      perror("server_handler");
      break;
    }
    
    /* No error */
    pos+=rc;
  }
}

/*
  This handler implements the server, running in its own thread.
  These handlers are created by threaded_server_handler
*/
void* server_handler(tcpip_connection* conn)
{


  tcpip_connection C;
  sigset_t sset;

  /* Make a local copy of conn and delete it. */
  COPY(C, conn);
  free(conn);

  /* Print a message to the user */
 // printf("Server: Connected to client %s:%d\n",
	// inet_ntoa(C.peer_addr.sin_addr), ntohs(C.peer_addr.sin_port));

  /* Make sure we block the SIGPIPE signal, else we may crash if the
     client closes the connection early. */
  sigemptyset(&sset);
  sigaddset(&sset, SIGPIPE);
  pthread_sigmask(SIG_BLOCK, &sset, NULL);

  /* Now write a message to the socket */

  //write_message(C.connfd, message);
  receive_message(C.connfd);

  /* Done, close the socket */
  (void) Close(C.connfd);	/* we do not handle the return value
				   here */
  return NULL;  
}

/*
  This is the handler given to the server, to start new
  connection threads. 
 */
void* threaded_server_handler(tcpip_connection* conn)
{
  pthread_t server_handler_thread;
  tcpip_connection* arg;
  int rc;

  /* Make a copy of conn, to give to the new thread */
  arg = OBJDUP(*conn);
 
  /* Start the new thread */
  rc = pthread_create(&server_handler_thread, NULL,
		      (thread_proc) server_handler, arg);

  /* If thread was not started successfully, abort */
  if(rc) FATAL_PERROR(rc);
  return NULL;
}

/*
  This global variable holds the server socket fd.
 */
int serverfd;

/* Signal handler for SIGURG, used to terminate the server.
   It does nothing itself, but the thread blocked in "accept" is
   resterted (returns EINTR, and then EBADF). */
void urg_handler(int i) { }

/* This is the thread_proc to call the server. It sets up signal
   handling for terminating the server.*/
void* server_thread(void* p)
{
  struct sigaction sa;
  sa.sa_handler = urg_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;

  CHECK_ERRNO(sigaction(SIGURG, &sa, NULL));

  server(serverfd, threaded_server_handler);
  return NULL;
}

/**
   Client functions.
**/

/*
  Read a message from the given socket and print it to the standard
  output.
 */
void receive_message(int fd)
{

  List MyList,MyList2,MyList3;
  List_init(&MyList);
  List_init(&MyList2);
  List_init(&MyList3);
  char buffer[1000];
  int rc,search;
  int metavlhth=0;
  char *wanted;
  char *path;
  char *type_req;
  char *page;
  char *pattern;
  char *pattern_final;
  char *all_finds;
  char *html3;
  int i=0,j=0;


  while(1) {
  doread:
  rc = read(fd, buffer, 100);
    if(rc==-1) {
      if(errno==EINTR) goto doread;
      perror("client_handler");
      break;
    }

    if(rc==0) {

      break;
    }

    /* Ok, we read something, so print it. */
    buffer[rc]='\0';  /* Make sure buffer is zero-terminated */
    //fputs(buffer, stdout);

/* O buffer periexei to mhnuma aithshs. Emeis xwrizoume ton buffer arxika ekei pou uparxei
   sto mhnuma \r\n opou diaxwrizontai oi grammes oi grammes kai apo8hkeuoume to 1o stoixeio,
   dhladh ekeino pou periexei thn methodo kai to path pou xreiazomaste, se mia lista.
   Epeita spame auth th lista  opou uparxei keno kai kratwntas to 1o stoixeio vriskoume tin methodo
   Epeidh theloume na to kanoume mono mia fora xrhsimopoioume kai th metavlhth i se sunthiki */

    	if(i==0)
    	{
    		strsplit(buffer,"\r\n", &MyList);
        	wanted = List_at(&MyList,0);
        	List_clear(&MyList);


        	strsplit(wanted," ", &MyList2);

        	type_req= List_at(&MyList2,0);
        	i=1;

    	}
    			/*An h methodos einai GET vriskoume to path me ton idio tropo*/
        		if(metavlhth==0 && (strcmp(type_req,"GET")==0))
        		{

        			List_init(&MyList);
        			strsplit(buffer,"\r\n", &MyList);
        			wanted = List_at(&MyList,0);
        			List_clear(&MyList);


        			strsplit(wanted," ", &MyList2);
        			path= List_at(&MyList2,1);

        			page=convert_to_html(path);
        			write_message(fd,page);         /*Ektupwsh sthn othonh tou pc se glwssa html*/
        			metavlhth=1;


        		}
        		/*Ean h methodos einai POST tote vriskoume to pattern me paromoio tropo opws kai prin(me thn sunarthsh strsplit)
        		  kai to pairname mazi me to path sth sunarthsh find*/
        		else if(strcmp(type_req,"POST")==0)
        		{

        			 List_init(&MyList3);
        			 search=strsplit(buffer,"pattern=",&MyList3);

        		 	 if(search>1)  /*Shmainei pws uparxei to pattern */
        		 	 {
        		 		strsplit(buffer,"\r\n", &MyList);
        		 		wanted = List_at(&MyList,0);
        		 		List_clear(&MyList);


        		 		 strsplit(wanted," ", &MyList2);
        		 		 path= List_at(&MyList2,1);

        		 		 pattern = List_at(&MyList3,1);

        		 		 pattern_final=www_form_urldecode(pattern);
        		 		 //printf("\nfinal_pattern== %s\n",pattern_final);
        		 		 html3=find(path,pattern);
        		 		 write_message(fd,html3);

        		 	 }
        		}
        		else if(j==0 && metavlhth==0)
        		{

        			write_message(fd, RE400);
        			j=1;

        		}
  }


  /* We are done! */
  if(rc==0) puts("\n"); /* If all went well, print 2 newlines */

}

/* Sunarthsh pou vriskei se ena path ta directories h ta files pou zhtountai kai ta epistrefei se glwssa html*/
char* find(char *path,char *pattern)
{
	char *html3;
	pid_t pid;


	int fdp[2];

	if (pipe(fdp)){
		fprintf(stderr,"Error creating pipe\n");
		exit(EXIT_FAILURE);
	}

	char *first=path;
	char *second="-name";
	char *third=pattern;
	char *fourth="-print";

	pid=fork();

	if (pid==-1){
		fprintf(stderr,"Error on creating proccess...exiting\n");
		exit(EXIT_FAILURE);
	}

	if (!pid)
	{
		close(fdp[0]);
		dup2(fdp[1],1);

		execl("/usr/bin/find","find",first,second,third,fourth,(char*)0);

		_exit(EXIT_SUCCESS);
	}
	else
	{
		FILE *fprd;
		char buffer[1024];
		int list_elem,i=0;
		int byte;
		char *element;

		List MyList;
		List_init(&MyList);
		close(fdp[1]);

		fprd=fdopen(fdp[0],"r");
		byte = fread (buffer, 1, sizeof (buffer), fprd); //vazoume ston buffer ta apotelesmata tis execl

		/*emfanizoume stin konsola to find(auto 8eloume na emfanisoume kai se html */
//		while(i<list_elem-1)
//		{
//			element=List_at(&MyList,i);
//			printf("%s\n",element);
//			i++;
//
//		}

		/*kaloume tin find_Elements me orismata tin lista pou ftiaksame kai to path  */
		html3=find_Elements(buffer,path);
		fclose(fprd);
	}

	return html3;

}


/*sunarthsh pou metatrepei se html ta apotelesmata tou find */

char* find_Elements(char *buffer,char *path){

   char *html;
   char *all_paths;
   char *size;
   char *type;
   char *html_all;
   char *html2;
   List lst;
   List_init(&lst);
   int list_elem;
   struct stat statbuf;

   list_elem=strsplit(buffer,"\n",&lst);     //apo ton buffer afou spasoume ta stoixeia se grammes ta apothikeuoume se mia lista
   int i=0;


   while(i<list_elem-1){

	   html=strconcat("<tr><td>",List_at(&lst,i),"<td></tr>",NULL);
	   html_all=strconcat(html_all,html,NULL);
	   i++;
   }
   /*Enwnoume ola ta html parts */
   html2=strconcat(first_html,path,forma,second_html,html_all,last_html,NULL);
   return html2;

//   	DIR           *d;
//	struct dirent *dir;

//	d = opendir(path);
//	if (d)
//	{

//	 dir = readdir(d);

//   for(i=0;i<list_elem-1;i++)
//   {
//      d = opendir(List_at(&lst,i));
//      if (d)
//      {
//    	 dir = readdir(d);
//
//
//			   	if (lstat(List_at(&lst,i), &statbuf))
//			   	{
//			    	    perror(List_at(&lst,i));
//			    }
//		    	else
//		    	{
//
//		    			if (S_ISDIR(statbuf.st_mode))
//		    			{
//		 							type="Directory";
//	   								//printf("%s is a directory\n", all_paths);
//		 							html=strconcat("<tr><td><a href=",List_at(&lst,i),">",dir->d_name,"</a></td><td>",type,"</td></tr>",NULL);
//		 							i++;
//		    			}
//		    			if (S_ISREG(statbuf.st_mode))
//		 				{
//		    					type="File";
//		  						//printf("%s is a plain file\n",all_paths);
//		    					sprintf(size,"%llu",statbuf.st_size);
//
//
//		    					html=strconcat("<tr><td>",dir->d_name,"</td><td>",type,"</td><td>",size,"<td></tr>",NULL);
//		    					i++;
//		   				}
//				}
//			   	html_all=strconcat(html_all,html,NULL);
//     }
//      closedir(d);
//   }
//   html2=strconcat(first_html,path,FORM,second_html,html_all,last_html,NULL);
//   return html2;

}






/*Sunarthsh pou pairnei to path kai anoigwntas to metatrepei ola ta stoixeia tou se glwssa html
  (diakrinei poia einai directories, poia files kai poso xwro katalamvanoun sthn mnhmh ktl.)
  kai ta epistrefei gia na graftoun */
char* convert_to_html(char *path)
{

	  char *html;
	  char *all_paths;
	  char *size;
	  char *type;
	  char *html_all;
	  char *html2;


	  DIR           *d;
	  struct dirent *dir;

	  d = opendir(path);
	  if (d)
	  {

		while ((dir = readdir(d)) != NULL)
	    {

	      struct stat statbuf;
	      all_paths=strconcat(path,"/",dir->d_name,NULL);


	    	if (lstat(all_paths, &statbuf)) { /* Get file attributes about FILE and put them in BUF.*/
	    	    perror(all_paths);


	    	}
	    	else
	    	{

	    	    if (S_ISDIR(statbuf.st_mode))
	    	    {
	    	    	type="Directory";
					html=strconcat("<tr><td><a href=",all_paths,">",dir->d_name,"</a></td><td>",type,"</td></tr>",NULL);
	    	    }
	    	    if (S_ISREG(statbuf.st_mode))
	    	    {
	    	    	type="File";
	    			sprintf(size,"%llu",statbuf.st_size);  /*Me thn entolh auth metrame to size */
	    			html=strconcat("<tr><td>",dir->d_name,"</td><td>",type,"</td><td>",size,"<td></tr>",NULL);
	    	    }

	    	}
	    	html_all=strconcat(html_all,html,NULL);  /*Enwnoume anadromika ola ta html parts */
	    }
	    closedir(d);

	  }


	html2=strconcat(first_html,path,forma,second_html,html_all,last_html,NULL);


	return html2;
}



 /*
  This function handles the client side of a connection to the
  server.
 */

void* client_handler(tcpip_connection* conn)
{
  tcpip_connection C;

  /* Copy and free conn */
  COPY(C, conn);
  free(conn);

  /* print a message to the user */
  //printf("Client: Connected to server %s:%d\n",
	// inet_ntoa(C.peer_addr.sin_addr), ntohs(C.peer_addr.sin_port));

  /* Receive a message from server and print it. */
  receive_message(C.connfd);
  

  Close(C.connfd);	       /* we do not handle the return value */

  return NULL;
}

/*
  This is the entry routine to a client. It opens a connection
  to the server and calls client_handler.
 */
void client()
{
  struct addrinfo* addr;
  int addr_rc;
  tcpip_connection* conn;

  /* First, get the server address */
  addr_rc = get_client_address("localhost", 3331, &addr);
  if(addr_rc) {
    FATAL_ERROR( gai_strerror(addr_rc) );
  }

  /* now create a connection */
  conn = client_connect(addr);

  if(conn==NULL) {
    FATAL_ERROR("We did not manage to connect!");
  }

  client_handler(conn);
}

/*
  You know ... main.
 */

int main()
{
  pthread_t server_tid;
  int rc;


  /* Create a server socket on port 11880 */
  serverfd = create_server_socket(11880);

  /* Start a thread for the server */
  rc = pthread_create(&server_tid, NULL,
		     server_thread, NULL);

  //client();
  getchar();
  /* Wait for server to exit */
  CHECK_ERRNO(Close(serverfd));
  pthread_kill(server_tid, SIGURG);
  pthread_join(server_tid,NULL);
  
  return 0;
}

