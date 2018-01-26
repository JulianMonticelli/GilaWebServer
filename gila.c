#include <string.h> // may not need
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> // still unsure if the directory name is left over from ARPAnet - if so, then, that's _really_ cool https://en.wikipedia.org/wiki/History_of_the_Internet#ARPANET
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>

/*************************************
* GILA (c) 2016 Julian Monticelli
* <jmm337@pitt.edu>
*
* A very lightweight HTTP web
* server, as requested to be made
* for a project in CS0449 at the
* University of Pittsburgh under
* Wonsun Ahn, and actually turned
* out to be a very cool project.
*
* Security is NOT my concern currently
* and was not asked to be of concern
* in project description.
*
* This is actually VERY insecure -
* it pulls ALL files as HTML files... 
* including binary (and source code
* if in the same folder)
* ... which can be decompiled
* and searched through for 
* security flaws. :S
*
* The Gila are an Apache tribe,
* and this program is named as such
* to parody the Apache HTTP server. :)
**************************************/




// --- STATIC CONST --- //
static const int BACKLOG_MAX = 100; // How many queued connections (backlog) we will allow at a time
static const int PORT = 50820; // HTTP TCP port (was assigned port for project)
static const int SHOW_HEADER = 1; // this will display startup information
static const int SOCKET_BUFFER_SIZE = 8192;
static const int VER_MAJ = 0; // version major number
static const int VER_MINOR = 1; // version minor number

// --- GLOBAL VARIABLES --- //
//int connections; // number of connections that currently exist


int bind_fd; // Socket bind file descriptor
int listen_fd; // Socket listener file descriptor
int socket_fd; // Socket file descriptor
struct sockaddr_in addr;


// -- LOG FILE AND MUTEX -- //
FILE * log_file;
pthread_mutex_t mutex_global = PTHREAD_MUTEX_INITIALIZER;

/************************
* Init relevant socket
* information to make
* the server function.
************************/
void init() {
	socket_fd = socket(PF_INET, SOCK_STREAM, 0); // Initialize socket file descriptor using PF_INET to a SOCK_STREAM
	//connections = 0; // init connections
	
	// Make sure that the socket creation succeeded
	if(socket_fd == -1) { //!! maybe I can change this to < 0? Will have to look into that.
		printf("ERROR: Initializing the socket failed."); //!! Not all too descriptive
		exit(-1);
	}
	
	// Set up some address & port information
	memset(&addr, 0, sizeof(addr)); // Set address to 0.0.0.0 via setting whole struct to 0's
	addr.sin_family = AF_INET; // Set socket family to AF_INET (same as PF_INET is what I read - not sure)
	addr.sin_port = htons(PORT); // Convert network byte order to host byte order
	addr.sin_addr.s_addr = INADDR_ANY; // Allows connections from ANY interface (localhost/LAN/external)
	
	// Bind socket to address incoming address
	bind_fd = bind(socket_fd, (struct sockaddr *)&addr, sizeof(addr)); // Bind sock_fd to addr and assign FD bind_fd
	if(bind_fd == -1) {
		printf("ERROR: Failed to bind socket with socket address.");
		exit(-2);
	}
	
	// Create listener
	listen_fd = listen(socket_fd, BACKLOG_MAX); // Create listener with max backlog sign
	if(listen_fd == -1) {
		printf("ERROR: Listen failed.");
		exit(-3);
	}
	
	// PRINT SECTION OF init()
	char * udl = "#############################################\n";
	char * nil = "#                                           #\n";
	char * pil = "#              GILA HTTP Server             #\n";
	char * cil = "#      by Julian Monticelli (c) 2016 :)     #\n";
	char * hgd = "# I, personally, hope you have a great day. #\n";
	printf("%s%s%s%s%s%s%s\n\nRunning version:\tv%d.%d\n\n",udl,nil,pil,cil,hgd,nil,udl,VER_MAJ,VER_MINOR);
	return;
}

/*******************************************************
* Log client requests 
*******************************************************/
void * log_request(void * buff_pointer) {
	char * request_buff = (char *) buff_pointer;
	int log_buff_size = strlen(request_buff); // Get log write size in bytes
	
	// -- CRITICAL SECTION -- //
	pthread_mutex_lock(&mutex_global); // Lock critical section
	
	// Open file 
	log_file = fopen("stats.txt", "a"); // FOPEN log file :)
	
	// Write to file
	fwrite(request_buff, 1, log_buff_size, log_file);
	
	// Close file
	fclose(log_file);
	
	pthread_mutex_unlock(&mutex_global); // Unlock critical section
	// -- END OF CRITICAL SECTION -- //
	
	free(request_buff); // Free the malloc'd buffer
	pthread_exit(NULL); // Exit current thread
}


/******************************************************
* Just grabs file size for a file for HTML headers.
*******************************************************/
int get_file_size(FILE * f) {
	fseek(f, 0, SEEK_END); // Seek to the end of file
	int size = ftell(f); // Get current file pointer
	fseek(f, 0, SEEK_SET); // Seek back to beginning of the file
	return size;
}


/******************************************************
* Handles a request to the HTTP server and will be 
* called after a request has been recieved. Shall spawn
* in a worker thread, but will lock critical data when
* sending sockets (because they use different IP 
* addresses).
*******************************************************/
void * handleClient(void * malloced_connfd) {
	int connfd = *((int *)malloced_connfd);
	int i = 0;
	int message_ready = 0;
	char buff[SOCKET_BUFFER_SIZE];
	char address_path[512];
	FILE * f;
	
	// Clear both buffers - technically, not entirely necessary to go the whole way but whatever - guarantees NULL bytes
	for(i = 0; i < SOCKET_BUFFER_SIZE; i++) {
		buff[i] = (char)0;
	}
	for(i = 0; i < 512; i++) {
		address_path[i] = (char)0;
	}
	
	// Gather message
	recv(connfd, buff, SOCKET_BUFFER_SIZE, 0);
	// Get message request
	if(buff[0] == 'G' && buff[1] == 'E' && buff[2] == 'T') { // GET
		int address_buff_ind = 5; // 5 [0-4] = "GET /"
		while(buff[address_buff_ind] != ' ') {
			address_path[address_buff_ind-5] = buff[address_buff_ind++];
		}
		#ifdef DEBUG
		printf("\nAddress: \"%s\"", address_path); // Print address if debug
		#endif
		f = fopen(address_path, "r"); // OPEN the file
		// ------------------------------------------------------------------------ //
		// While this could very well be one of the worst security choices, for now
		// I choose to leave it a result of laziness. The following check (f!=NULL)
		// does not dynamically check any file restrictions
		// ------------------------------------------------------------------------ //		
		if(f != NULL) { // IF THE FILE EXISTS (200):
		
			// Begin constructing response
			char * response_200_begin = "HTTP/1.1 200 OK\r\nDate:";
			char * response_200_conlen = "Content-Length: ";
			char content_length[10]; // We will support up to ~9MB pages - otherwise this will break (who has 10MB pages anyway?)
			snprintf(content_length, 8, "%d\r\n", get_file_size(f)); 
			char * response_200_h_end = "Content: close\r\nContent Type: text/html\r\n\r\n";
			
			//content_length = itoa(sizeof(f)); // Content length
			
			// Get time
			time_t rawtime; // cplusplus.com example helped me out here
			struct tm * time_info; // Declare time information struct
			time( &rawtime ); // "insert how many seconds from Jan 1, 1970 to rawtime pls"
			time_info = localtime( &rawtime ); // Get local time from raw time
			char * times = asctime( time_info ); // Get time info in string format
			
			// -- CREATE LOG ENTRY TO STATS -- //
			char * log_entry = malloc(768); // I'd really hope our log entry wouldn't actually take up 0.75 KB, but for REALLY long requests (since address is 512 char max)
			
			struct sockaddr_in addr;
			socklen_t addr_size = sizeof(struct sockaddr_in);
			int res = getpeername(connfd, (struct sockaddr *)&addr, &addr_size);
			strcpy(log_entry, inet_ntoa(addr.sin_addr));
			char * str1 = " @ ";
			char times2[16];
			strftime(times2, 26, "%m/%d/%y %H:%M:%S", time_info);
			strcat(log_entry, str1);
			strcat(log_entry, times2);
			char * str2 = ":\r\n";
			strcat(log_entry, str2);
			
			// Break apart buff into separate Strings
			char req[544]; // assuming up to 512-byte addres + 32 bytes
			char host[128]; //
			char user_agent[96]; // I don't want long UA strings - I just want the first bit of information
			i = 0; // set i = 0
			
			// GET request
			while(buff[i] != '\r') {
				req[i] = buff[i++];
			}
			req[i] = (char)0; // NULL-terminate string
			int past_get = i + 2; // start of next line
			
			// User-Agent strings
			i = past_get;
			while(buff[i] != 'U' && buff[i+1] != 's' && buff[i+2] != 'e' && buff[i+3] != 'r' && buff[i+4] != '-' && buff[i+5] != 'A' && i < sizeof(buff)) {
				while(buff[i] != '\r' && buff[i] != '\n') { // if we don't land on a \r or a \n...
					i += 2; // intelligently skip 2 characters!
				}
				if(buff[i] == '\r') { // carriage return?
					i += 2; // increment index by 2
				} else { // newline?
					i++; // increment index by 1
				}
			}
			
			int j = 0;
			if(buff[i] == 'U' && buff[i+1] == 's' && buff[i+2] == 'e' && buff[i+3] == 'r' && buff[i+4] == '-' && buff[i+5] == 'A') { // if nextline is User-Agent
				while(buff[i] != '\r' && j < 95) { // while we haven't hit \r and haven't hit index 95
					user_agent[j++] = buff[i++];
				}
				user_agent[j] = (char)0; // when we have hit max length OR User-Agent line is finished, terminate String
			} else { // we don't have a User-Agent string following GET request
				user_agent[0] = (char)0; // incase there was leftover data in the stack, just terminate user_agent from the beginning
			}
			//i += 2; // skip past \r and \n
			
			
			// Host
			i = past_get;
			j = 0;
			while(buff[i] != 'H' && buff[i+1] != 'o' && buff[i+2] != 's' && buff[i+3] != 't' && buff[i+4] != ':' && i < sizeof(buff)) { // While the current line is NOT host1 and we haven't exceeded buffer
				while(buff[i] != '\r' && buff[i] != '\n') { // if we don't land on a \r or a \n...
					i += 2; // intelligently skip 2 characters!
				}
				if(buff[i] == '\r') { // carriage return?
					i += 2; // increment index by 2
				} else { // newline?
					i++; // increment index by 1
				}
			}
			
			
			// if we hit here, we got to the Host string
			if(buff[i] == 'H' && buff[i+1] == 'o' && buff[i+2] == 's' && buff[i+3] == 't' && buff[i+4] == ':') {
				while(buff[i] != '\r' && j < 128) { // while we haven't hit \r and haven't hit index 95
					host[j++] = buff[i++];
				}
				host[j] = (char)0; // when we have hit max length OR User-Agent line is finished, terminate String
			}
			
			
			char * str3 = "\r\n"; // MAYBE we won't need all these
			strcat(log_entry, req);
			strcat(log_entry, str3);
			strcat(log_entry, host);
			strcat(log_entry, str3);
			strcat(log_entry, user_agent);
			strcat(log_entry, str3);
			strcat(log_entry, str3);
			
			printf("%s : %s\n", inet_ntoa(addr.sin_addr), req);
			// Spawn worker thread to write
			pthread_t log_thread; // Create worker to write to stats.txt
			pthread_create(&log_thread, NULL, &log_request, (void *)log_entry); // Create thread to 
			
			// -- END LOG ENTRY TO STATS -- //
			
			// Clear buffer again
			for(i = 0; i < SOCKET_BUFFER_SIZE; i++) {
				buff[i] = (char)0;
			}
			i = 0;
			
			// Create HTML header
			char header[100];
			for(i = 0; i < 100; i++) {
				header[i] = (char)0; // Zero-ify
			}
			strcpy(header, response_200_begin); //  header = response_200_begin
			strcat(header, times); // + times
			strcat(header, response_200_conlen); // + response_200_conlen
			strcat(header, content_length); // + content_length
			strcat(header, response_200_h_end);	// + response_200_h_end ;
			
			// Copy header and message to buffer
			int header_len = strlen(header);
			int message_len = get_file_size(f);
			int response_len = header_len + message_len;
			for(i = 0; i < header_len; i++) {
				buff[i] = header[i];
			}
			if((response_len + 4) > SOCKET_BUFFER_SIZE ) { // do we need to increase buffer size?
				char big_buffer[response_len+4];
				for(i = 0; i < header_len; i++) {
					big_buffer[i] = header[i];
				}
				char msg_body[message_len];
				char * buf = big_buffer + i;
				fread(msg_body, message_len, 1, f);
				strcat(big_buffer, msg_body);
				for(i = response_len; i < response_len + 4; i += 2) {
					big_buffer[i] = '\r';
					big_buffer[i+1] = '\n';
				}
				#ifdef DEBUG
				printf("%s\n", buff); // Print buffer if in debug
				#endif
				send(connfd, big_buffer, sizeof(big_buffer), 0);
			} else {
				char msg_body[message_len];
				fread(msg_body, message_len, 1, f);
				strcat(buff, msg_body);
				for(i = response_len; i < response_len + 4; i += 2) {
					buff[i] = '\r';
					buff[i+1] = '\n';
				}
				#ifdef DEBUG
				printf("%s\n", buff); // Print buffer if in debug
				#endif
				send(connfd, buff, sizeof(buff), 0);
			}
		} else { // IF THE FILE DOESN'T EXIST (404):
			// Clear buffer again
			for(i = 0; i < SOCKET_BUFFER_SIZE; i++) {
				buff[i] = (char)0;
			}
			strcpy(buff, "HTTP/1.1 404 Not Found"); // 404
			#ifdef DEBUG
			printf("%s\n", buff); // Print out 404 Buffer if in DEBUG
			#endif
			send(connfd, buff, strlen(buff), 0); // send 404 back
		}
	}
	
	// close worker thread
	close(connfd);
	free(malloced_connfd); // free arg
	pthread_exit(NULL); // exit thread :)
	return;
}
/******************************************************
* The main() method just includes the while loop and 
* startup procedure.
*******************************************************/
int main() {
	// Init the program
	init(); // display header information once
	// Loop until forcefully interrupted
	while(1) {
		int conn_fd = accept(socket_fd, NULL, NULL); // Accept connection
		int * malloced_connfd = malloc(sizeof(int));
		*malloced_connfd = conn_fd;
		if(conn_fd == -1) {
			printf("ERROR: Failed to accept connection.");
			exit(-4);
		}
		// Create new worker
		pthread_t worker;
		pthread_create(&worker, NULL, &handleClient, malloced_connfd);
		// we don't join because that halts thread - we, instead, want to pthread_exit() inside the thread
		// pthread_join(&worker, NULL);
	}
	return 0;
}