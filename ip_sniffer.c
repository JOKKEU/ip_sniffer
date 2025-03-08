#include "ip_sniffer.h"


static void init_params(struct parameters* params, char** arr_args)
{

	if (arr_args == NULL || params == NULL || arr_args[1] == NULL || arr_args[2] == NULL || arr_args[3] == NULL) 
        {
		LOG("Insufficient or invalid arguments\n");
		exit(EXIT_FAILURE);
    	}
    	
	char* endptr;
	errno = 0;
	
	long index = strtol(arr_args[1], &endptr, 10);
	if (endptr == arr_args[1] || errno == ERANGE || index < INT_MIN || index > INT_MAX)
	{
		LOG("Invalid input for index operation: %s\n", arr_args[1]);
		exit(EXIT_FAILURE);
	}
	
	errno = 0;
	
	long id_op = strtol(arr_args[2], &endptr, 10);
	if (endptr == arr_args[2] || errno == ERANGE || id_op < INT_MIN || id_op > INT_MAX)
	{
		LOG("Invalid input for id operation: %s\n", arr_args[2]);
		exit(EXIT_FAILURE);
	}
	
	errno = 0;
	long time_work = strtol(arr_args[3], &endptr, 10);
	if (endptr == arr_args[3] || errno == ERANGE || time_work < INT_MIN || time_work > INT_MAX)
	{
		LOG("Invalid input for logging time operation: %s\n", arr_args[3]);
		exit(EXIT_FAILURE);
	}
	
	
	
	errno = 		0;
	strncpy(params->filename, arr_args[4], 30);
	params->id_op = 	(uint32_t)id_op;
	params->time_work = 	(uint32_t)time_work;
	params->iface_index = 	(uint32_t)index;
}



static void set_rt_process(void)
{
	struct sched_param sched_p;
	sched_getparam(getpid(), &sched_p);
	sched_p.sched_priority = 49;	// RT prio 
	sched_setscheduler(getpid(), SCHED_FIFO, &sched_p);	
}


#ifdef __BUFFERING

static void bubble_sort_descending(struct ip_data* ip_d) 
{
	for (size_t index = 0; index < ip_d->count_buffers - 1; ++index) 
	{
        	for (size_t j = 0; j < ip_d->count_buffers - index - 1; j++) 
        	{
            		if (ip_d->data_bytes[j] < ip_d->data_bytes[j + 1]) 
            		{ 
                		size_t temp = ip_d->data_bytes[j];
                		ip_d->data_bytes[j] = ip_d->data_bytes[j + 1];
               		 	ip_d->data_bytes[j + 1] = temp;
            		}
       	 	}
    	}
}



static void buffer_log(struct ip_data* ip_d, struct parameters* params)
{
	bubble_sort_descending(ip_d);
	for (size_t index = 0; index < ip_d->count_buffers; ++index)
	{
		if (ip_d->data_bytes[index] == 0) {continue;}
		LOG("================================\n");
		LOG("[%u] source IP:PORT - %s\n", index, ip_d->buffers_ip_port[index]);
		LOG("Receive from this IP - %lu bytes\n", ip_d->data_bytes[index]);
		LOG("================================\n\n");
	}
	
	if (strcmp(params->filename, "-") == 0) { return; }

    // Исправляем открытие файла
	int fd = open(params->filename, O_RDWR | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
	if (fd < 0) 
	{
		perror("Open file error");
		exit(EXIT_FAILURE);
	}

	char file_out[4096];

	for (size_t index = 0; index < ip_d->count_buffers; ++index)
	{
		if (ip_d->data_bytes[index] == 0) { continue; }
		snprintf(file_out, sizeof(file_out), "================================\n"
		                                    "[%u] source IP:PORT - %s\n"
		                                    "Receive from this IP - %lu bytes\n"
		                                    "================================\n\n",
		         index, ip_d->buffers_ip_port[index], ip_d->data_bytes[index]);

		if (write(fd, file_out, strlen(file_out)) < 0) 
		{
		    perror("Write to file error");
		    close(fd);
		    exit(EXIT_FAILURE);
		}
	}
    	close(fd);
    	
    	LOG("writing to file was successful\n");
		
}

#endif // __BUFFERING

static void finally_log(struct my_packet_data* mpd, struct parameters* params)
{
	LOG("all receive bytes : %lu\n", mpd->count_all_receive_bytes);
	LOG("sniff time: %u\n\n", time(&params->time_end) - params->time_start);
}


#ifdef __BUFFERING

static int init_ip_data(struct ip_data* ip_d)
{
	ip_d->buffer_size = BUFFER_SIZE;	
	
	ip_d->buffers_ip_port = (char*)malloc( sizeof(char*) * ip_d->buffer_size);
	
	if (ip_d->buffers_ip_port == NULL)
	{
		perror("buffers_ip_port alloc error");
		return EXIT_FAILURE;
	}
			
	ip_d->data_bytes = (size_t*)malloc(sizeof(size_t*) * ip_d->buffer_size);
	if (ip_d->data_bytes == NULL)
	{
		perror("data_bytes alloc error");
		return EXIT_FAILURE;
	}
	
	for (size_t i = 0; i < ip_d->buffer_size; ++i)
	{
		ip_d->buffers_ip_port[i] = (char*)malloc(sizeof (char) * 30);
		if (ip_d->buffers_ip_port[i] == NULL)
		{
			perror("params alloc error");
			for (size_t j = 0; j < i; ++j)
			{
				free(ip_d->buffers_ip_port[j]);
			}
			return EXIT_FAILURE;
		
		}
	}
		
	return EXIT_SUCCESS;
}	
	

static void copy_data_to_buffer(struct ip_data* ip_d, const char* ip_name, ssize_t bytes)
{
	if (ip_d->count_buffers >= ip_d->buffer_size - 1)
    	{

		size_t new_size = ip_d->buffer_size + 30;
		
		char** temp_b_i_p = realloc(ip_d->buffers_ip_port, sizeof(char*) * new_size);
		if (temp_b_i_p == NULL) 
		{
		    	perror("Failed to reallocate memory for buffers_ip_port");
		    	exit(EXIT_FAILURE);
		}
		

		size_t* temp_d_b = realloc(ip_d->data_bytes, sizeof(size_t) * new_size);
		if (temp_d_b == NULL)
		{
			perror("Failed to reallocate memory for data_bytes");
			free(temp_b_i_p);
			exit(EXIT_FAILURE);
		}

		ip_d->buffers_ip_port = temp_b_i_p;
		ip_d->data_bytes = 	temp_d_b;
		ip_d->buffer_size =	new_size;
		
		for (size_t i = ip_d->count_buffers; i < new_size; ++i) 
		{
		    ip_d->buffers_ip_port[i] = malloc(30 * sizeof(char));
		    if (ip_d->buffers_ip_port[i] == NULL) 
		    {
		        perror("Failed to allocate memory for buffer string");
		        exit(EXIT_FAILURE);
		    }
		    ip_d->data_bytes[i] = 0;
		}

		LOG("Reallocation successful: buffer_size updated to %lu\n", ip_d->buffer_size);
	}

   	if (ip_d->buffers_ip_port != NULL)
	{
	    	size_t index = 0;
	    	
	    	for ( ; index < ip_d->count_buffers; ++index)
	    	{
	    		if (strcmp(ip_name, ip_d->buffers_ip_port[index]) == 0)
	    		{
	    			
				strncpy(ip_d->buffers_ip_port[index], ip_name, 30);
				ip_d->buffers_ip_port[index][29] = '\0';
				ip_d->data_bytes[index] += bytes;
				goto out;
	    		}
	    	}
	    	
	    	
		strncpy(ip_d->buffers_ip_port[index++], ip_name, 30);
		ip_d->buffers_ip_port[index][29] = '\0';
		ip_d->data_bytes[index++] += bytes;
		ip_d->count_buffers++;
		
out:
    	}
}


static void cleanup_ip_data_buffers(struct ip_data* ip_d)
{
	for (size_t i = 0; i < ip_d->buffer_size; ++i)
	{
		free(ip_d->buffers_ip_port[i]);
	}
	
}

#endif // __BUFFERING


static char getch(void)
{
	struct termios oldt, newt;
	char ch;
	
	tcgetattr(STDIN_FILENO, &oldt);
	newt = oldt;
	
	newt.c_lflag &= ~(ICANON | ECHO);
	tcsetattr(STDIN_FILENO, TCSANOW, &newt);
	
	ch = getchar();
	
	tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
	
	return ch;
}

static void* getch_for_thread(void* arg)
{
	set_rt_process();
	char ch;
	flags* flag = (flags*)arg;
	
	while(*(flag->run_flag) == true) 
	{
		if ((ch = getch()) == ENTER)
		{
			*(flag->run_flag) = false;
		}
	}
	
	return NULL;
}


#define __START_INIT_IP_DATA 					\
char ip_name[30];						\
ip_d->buffer_size = 		BUFFER_SIZE;			\
ip_d->cleanup_buffers = 	cleanup_ip_data_buffers;	\
ip_d->count_buffers = 		0;				\
if (init_ip_data(ip_d) != 0) {return EXIT_FAILURE;}






int sniffer(int count_argc, char** arr_args)
{
	set_rt_process();
	if (arr_args[1] == NULL)
	{
		LOG("enter --help for help information\n");
		return EXIT_SUCCESS;
	}
	
	else if ((strcmp(arr_args[1], "--help") == 0))
	{	
		LOG("help information:\n\n");
		LOG("BE CARE!!! program displayed approximate values and working in RT mode, sometimes more bytes can come from one IP than from all IPs.\n");
		LOG("sudo ./sniffer [iface index (example: 1] [id operation] [sniff time (sec)] [filename]\n");
		LOG("after the program is finished, will output a sorted array consisting of IP:PORT and the number of bytes received\n");
		LOG("iface_name -   the interface you want to listen to | 1 - localhost, 2 - ...\n");
		LOG("id operation - the operation you want to perform\n");
		LOG("sniff time -   wiretapping time (sec) | 0 or 1 - at the touch of a button ENTER for stop\n");
		LOG("filename -      enter filename for safe result | if you don't need to enter '-'\n\n");
		LOG("[ID 1] (enter random number for iface index) simple logging receive packets\n");
		LOG("[ID 2] simple sniff receive packets + ip sender(local) on a specific interface\n");
		LOG("[ID 3] simple sniff receive packets(TCP)+ ip sender(global) on a specific interface\n");
		LOG("[ID 4] simple sniff receive packets(UDP)+ ip sender(global) on a specific interface\n");
		return EXIT_SUCCESS;
	}
	
	else if (count_argc == 5) {goto next_stage;}
		
	else 
	{
		LOG("enter --help for help information\n");
		return EXIT_SUCCESS;
	}
	
next_stage:

	
	struct parameters* params = (struct parameters*)malloc(sizeof (struct parameters));
	if (params == NULL)
	{
		perror("params alloc error");
		return EXIT_FAILURE;
	}
	
	
	init_params(params, arr_args);
	
	if (params->id_op == 0) 
	{
		LOG("enter --help for help information\n");
		return EXIT_SUCCESS;
	}
	
	LOG("iface index: %d | id op: %u | sniff time (sec): %u | filename: %s\n", params->iface_index, params->id_op, params->time_work, params->filename);
	
	struct my_packet_data* mpd = (struct my_packet_data*)malloc(sizeof (struct my_packet_data));
	if (mpd == NULL)
	{
		perror("mpd alloc error");
		return EXIT_FAILURE;
	}
	
	uint8_t rn_flag = 	true;
	flags flag_thread = 	{.run_flag = &rn_flag};
	
	struct thread_data* thrdd;
	if (params->time_work == 0 || params->time_work == 1)
	{
		thrdd = (struct thread_data*)malloc(sizeof (struct thread_data));
		if (thrdd == NULL)
		{
			perror("thrdd alloc error");
			return EXIT_FAILURE;
		}
		

		pthread_mutex_init(&thrdd->mutex, NULL);
		thrdd->func = getch_for_thread;

		if ((pthread_create(&thrdd->thread, NULL, thrdd->func, (void*)&flag_thread)) != 0) 
		{
			perror("pthread_create failed");
			return EXIT_SUCCESS;
		}
	}
	
	
	
	mpd->data_size =		 0;
	mpd->count_all_receive_bytes = 	 0;
	mpd->sockfd = 			 0;
	mpd->buffer_packet = 		(char*)malloc(MTU);
	
	if (mpd->buffer_packet == NULL)
	{
		perror("buffer_packet alloc error");
		return EXIT_FAILURE;
	}
	
	mpd->source_packet_len = sizeof(struct sockaddr);
	
	
	if (params->id_op == 3)
	{
		mpd->sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
		if (mpd->sockfd < 0)
		{
			perror("socket create error");
			return EXIT_FAILURE;
		}
		
	}
	
	else if (params->id_op == 4)
	{
		mpd->sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
		if (mpd->sockfd < 0)
		{
			perror("socket create error");
			return EXIT_FAILURE;
		}
	} 
	
	else
	{
		mpd->sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
		if (mpd->sockfd < 0)
		{
			perror("socket create error");
			return EXIT_FAILURE;
		}
	}
	
	
	
	mpd->source_packet = (struct sockaddr_in*)malloc(sizeof (struct sockaddr_in));
	if (mpd->source_packet == NULL)
	{
		perror("source_packet alloc error");
		return EXIT_FAILURE;
	}
	
	
	if (params->id_op == 1)
	{
		if (params->time_work != 0 || params->time_work != 1) {time(&params->time_start);}
		else  
		{
			time(&params->time_start);
		}
		
		while(rn_flag)
		{
			mpd->data_size = recvfrom(mpd->sockfd, mpd->buffer_packet, MTU, 0, (struct sockaddr_in*)mpd->source_packet, &mpd->source_packet_len);
			if (mpd->data_size < 0)
			{
				perror("failed receive packet");
				continue;
			}
			
			LOG("Receive packet: %ld bytes\n", mpd->data_size);
			mpd->count_all_receive_bytes += mpd->data_size;
			
			if (params->time_work == 0 || params->time_work == 1) {goto next_l1;}
			else if (time(&params->time_end) >= params->time_start + params->time_work) {break;}
next_l1:
		}
		
		finally_log(mpd, params);
	}
	
	
	if (params->id_op == 2)
	{
	
		mpd->saddrll = (struct sockaddr_ll*)malloc(sizeof (struct sockaddr_ll));
		if (mpd->saddrll == NULL)
		{
			perror("saddrll alloc error");
			return EXIT_FAILURE;
		}
		
#ifdef __BUFFERING		
		struct ip_data* ip_d = (struct ip_data*)malloc(sizeof (struct ip_data));
		if (ip_d == NULL)
		{
			perror("ip_d alloc error");
			return EXIT_FAILURE;
		}
		
		__START_INIT_IP_DATA

#endif // __BUFFERING
		mpd->saddrll_len = 		sizeof (struct sockaddr_ll);
		memset(mpd->saddrll, 0, mpd->saddrll_len);
		mpd->saddrll->sll_family = 	AF_PACKET;
		mpd->saddrll->sll_protocol = 	htons(ETH_P_ALL);
		mpd->saddrll->sll_ifindex = 	params->iface_index; 
		
		if (params->time_work != 0 || params->time_work != 1) {time(&params->time_start);}
		
		if (bind(mpd->sockfd, (struct sockaddr*)mpd->saddrll, mpd->saddrll_len ) < 0)
		{
			perror("Bind failed\n");
			close(mpd->sockfd);
			return EXIT_FAILURE;
		}
	
		while(rn_flag)
		{
			mpd->data_size = recvfrom(mpd->sockfd, mpd->buffer_packet, MTU, 0, (struct sockaddr*)mpd->saddrll, &mpd->saddrll_len);
			if (mpd->data_size < 0)
			{
				perror("failed receive packet");
				continue;
			}
			
			LOG("=========\n");
			LOG("Receive packet: %ld bytes\n", mpd->data_size);
			LOG("from ip - %s:%hu\n", inet_ntoa(mpd->source_packet->sin_addr), mpd->source_packet->sin_port);
			LOG("=========\n\n");
			mpd->count_all_receive_bytes += mpd->data_size;
			
			
#ifdef __BUFFERING		
			if (ip_d->buffers_ip_port != NULL)
			{
				snprintf(ip_name, 30, "%s:%hu", inet_ntoa(mpd->source_packet->sin_addr), mpd->source_packet->sin_port);
				
				copy_data_to_buffer(ip_d, ip_name, mpd->data_size);

			
			}
					
#endif // __BUFFERING	
			if (params->time_work == 0 || params->time_work == 1) {goto next_l2;}
			else if (time(&params->time_end) >= params->time_start + params->time_work) {break;}
next_l2:
		}
	
		
#ifdef  __BUFFERING	

		buffer_log(ip_d, params);
		
#endif // __BUFFERING
		finally_log(mpd, params);
		
#ifdef __BUFFERING		
		ip_d->cleanup_buffers;
		free(ip_d->data_bytes);
		free(ip_d);
#endif // __BUFFERING		

		free(mpd->saddrll);		
	}
	
	
	if (params->id_op == 3)
	{
	
		mpd->ip_header = (struct iphdr*)malloc(sizeof (struct iphdr));
		if (mpd->ip_header == NULL)
		{
			perror("ip_header alloc error");
			return EXIT_FAILURE;
		}
		
		mpd->tcp_header = (struct tcphdr*)malloc(sizeof (struct tcphdr));
		if (mpd->tcp_header == NULL)
		{
			perror("tcp_header alloc error");
			return EXIT_FAILURE;
		}
		
		
		struct ip_data* ip_d = (struct ip_data*)malloc(sizeof (struct ip_data));
		if (ip_d == NULL)
		{
			perror("ip_d alloc error");
			return EXIT_FAILURE;
		}
		
#ifdef __BUFFERING	

		__START_INIT_IP_DATA
		
#endif // __BUFFERING	
		
		
		
		if (params->time_work != 0 || params->time_work != 1) {time(&params->time_start);}
		else  
		{
			time(&params->time_start);
		}
		       
		while(rn_flag)	
		{
	
			mpd->data_size = recvfrom(mpd->sockfd, mpd->buffer_packet, MTU, 0, (struct sockaddr*)mpd->source_packet, &mpd->source_packet_len);
			if (mpd->data_size < 0)
			{
				perror("failed receive packet");
				return EXIT_SUCCESS;
			}
			
			memcpy(mpd->ip_header,  (struct iphdr*)mpd->buffer_packet, sizeof(struct iphdr));
			memcpy(mpd->tcp_header, (struct tcphdr*)(mpd->buffer_packet + mpd->ip_header->ihl * 4), sizeof(struct tcphdr));
			
			mpd->count_all_receive_bytes += mpd->data_size;
			
			LOG("=========\n");
			LOG("source\t\tip:port - %s:%d\n", inet_ntoa(*(struct in_addr*)&mpd->ip_header->saddr), ntohs(mpd->tcp_header->source));
			LOG("destination      ip:port - %s:%d\n", inet_ntoa(*(struct in_addr*)&mpd->ip_header->daddr), ntohs(mpd->tcp_header->dest));
			LOG("receive packet:  %ld bytes\n", mpd->data_size);
			LOG("=========\n\n");
			
			
#ifdef __BUFFERING			
			if (ip_d->buffers_ip_port != NULL)
			{
				snprintf(ip_name, 30, "%s:%hu", inet_ntoa(*(struct in_addr*)&mpd->ip_header->saddr), ntohs(mpd->tcp_header->source));
					
				copy_data_to_buffer(ip_d, ip_name, mpd->data_size);
				
												
			}
#endif // __BUFFERING

			
			if (params->time_work == 0 || params->time_work == 1) {goto next_l3;}
			else if (time(&params->time_end) >= params->time_start + params->time_work) {break;}
next_l3:
		}
		
		
		
#ifdef __BUFFERING		

		buffer_log(ip_d, params);
		
#endif // __BUFFERING
		finally_log(mpd, params);
		
#ifdef __BUFFERING	

		ip_d->cleanup_buffers;
		free(ip_d->data_bytes);
		free(ip_d);
		
#endif // __BUFFERING

		free(mpd->ip_header);
		free(mpd->tcp_header);
				
	}
	
	if (params->id_op == 4)
	{
	
		mpd->ip_header = (struct iphdr*)malloc(sizeof (struct iphdr));
		if (mpd->ip_header == NULL)
		{
			perror("ip_header alloc error");
			return EXIT_FAILURE;
		}
		
		mpd->udp_header = (struct udphdr*)malloc(sizeof (struct udphdr));
		if (mpd->udp_header == NULL)
		{
			perror("udp_header alloc error");
			return EXIT_FAILURE;
		}
		
		struct ip_data* ip_d = (struct ip_data*)malloc(sizeof (struct ip_data));
		if (ip_d == NULL)
		{
			perror("ip_d alloc error");
			return EXIT_FAILURE;
		}

#ifdef __BUFFERING
		
		__START_INIT_IP_DATA
		
#endif // __BUFFERING
		
		if (params->time_work != 0 || params->time_work != 1) {time(&params->time_start);}
		else  
		{
			time(&params->time_start);
		}
		
		while(rn_flag)
		{
	
			mpd->data_size = recvfrom(mpd->sockfd, mpd->buffer_packet, MTU, 0, (struct sockaddr*)mpd->source_packet, &mpd->source_packet_len);
			if (mpd->data_size < 0)
			{
				perror("failed receive packet");
				return EXIT_SUCCESS;
			}
			
			memcpy(mpd->ip_header,  (struct iphdr*)mpd->buffer_packet, sizeof(struct iphdr));
			memcpy(mpd->udp_header, (struct udphdr*)(mpd->buffer_packet + mpd->ip_header->ihl * 4), sizeof(struct udphdr));
			
			mpd->count_all_receive_bytes += mpd->data_size;
			
			
			LOG("=========\n");
			LOG("source\t\tip:port - %s:%d\n", inet_ntoa(*(struct in_addr*)&mpd->ip_header->saddr), ntohs(mpd->udp_header->source));
			LOG("destination      ip:port - %s:%d\n", inet_ntoa(*(struct in_addr*)&mpd->ip_header->daddr), ntohs(mpd->udp_header->dest));
			LOG("receive packet:  %ld bytes\n", mpd->data_size);
			LOG("=========\n\n");
			
#ifdef __BUFFERING
			
			if (ip_d->buffers_ip_port != NULL)
			{
				snprintf(ip_name, 30, "%s:%hu", inet_ntoa(*(struct in_addr*)&mpd->ip_header->saddr), ntohs(mpd->udp_header->source));
				
					
				copy_data_to_buffer(ip_d, ip_name, mpd->data_size);

										
			}
		
#endif // __BUFFERING
			
			if (params->time_work == 0 || params->time_work == 1) {goto next_l4;}
			else if (time(&params->time_end) >= params->time_start + params->time_work) {break;}
next_l4:
		
		}
		
	
#ifdef __BUFFERING		
		
		buffer_log(ip_d, params);
		
#endif // __BUFFERING
		
		finally_log(mpd, params);
		
#ifdef __BUFFERING
		
		ip_d->cleanup_buffers; 
		free(ip_d->data_bytes);
		free(ip_d);
		
#endif // __BUFFERING		

		free(mpd->ip_header);
		free(mpd->udp_header);
				
	}
	
	
	if (params->time_work == 0 || params->time_work == 1) 
	{
		pthread_join(thrdd->thread, NULL);
		free(thrdd);
	}
	
	
	close(mpd->sockfd);
	free(params);
	free(mpd->source_packet);
	free(mpd->buffer_packet);
	free(mpd);		
	return EXIT_SUCCESS;
}











