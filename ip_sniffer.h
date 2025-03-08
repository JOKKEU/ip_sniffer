#ifndef __IP_LOGGER__
#define __IP_LOGGER__


#include <arpa/inet.h>
#include <sys/socket.h>
#include <asm-generic/param.h>

#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h> 
#include <linux/ip.h>
#include <linux/in.h>


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>
#include <termios.h>
#include <pthread.h>
#include <sched.h>


#ifndef MTU
	#define MTU 		65536
#endif  // MTU

#define true 		1
#define false 		0
#define ENTER 		'\n'

#define LOG(...) 	fprintf(stdout, "(INFO) " __VA_ARGS__)

#define BUFFER_SIZE 50

#ifndef __BUFFERING
	#define __BUFFERING 1
#else
	#define __BUFFERING 0
#endif // __BUFFERING



typedef struct _FLAG 
{	
	uint8_t* 		run_flag;
	//uint8_t 		buffer_overflow_flag;
}flags;



extern struct thread_data
{
	void*			 (*func)(void*);
	pthread_t 		thread;
	pthread_mutex_t 	mutex;
};

extern struct ip_data
{
	size_t 			buffer_size;
	char** 			buffers_ip_port;
	void			(*cleanup_buffers)(struct ip_data*);
	size_t*  		data_bytes;
	size_t 			count_buffers;
};


extern struct parameters
{
	uint32_t 		time_work;
	uint32_t 		id_op;
	time_t 			time_start, time_end;
	uint32_t 		iface_index;
	char 			filename[30];
};

extern struct my_packet_data
{
	struct sockaddr_in* 	source_packet;
	socklen_t		source_packet_len;
	ssize_t 		data_size;
	size_t 			count_all_receive_bytes;
	char* 			buffer_packet;
	
	struct iphdr* 		ip_header;
	struct tcphdr* 		tcp_header;
	struct udphdr*		udp_header;
	
	struct sockaddr_ll* 	saddrll;
	socklen_t 		saddrll_len;
	int 			sockfd;
};


extern int sniffer(int, char**);

#define PACKET_SIZE 65536

#endif
