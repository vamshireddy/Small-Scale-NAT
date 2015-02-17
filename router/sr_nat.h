#include<stdio.h>



// This header file has all the definetions of the NAT structures and functions.


typedef struct nat_session
{
	uint32_t sub_ip;
	uint16_t sub_port;
	uint32_t nat_ip;
	uint16_t nat_port;
	/*
		Destination IP and PORT are optional. These are used only when the Address and port dependent filtering is used 
	*/
	uint32_t dst_ip;
	uint16_t dst_port;	
	time_t last_refresh_time; // Last time this session was used
	uint8_t direction;	// Direction of session initiation
}nat_session_t;


typedef struct nat_session_table
{
	nat_session_t* list;
	uint32_t count;
	// This is used to avoid race conditions and allow both the timer daemon, the session allocation and session display to run properly
	pthread_mutex_t* mutex;	
}nat_table_t;



