/***********************************
* file: sniffer.h
* written: 24/01/2017
* last modified: 26/01/2017
* synopsis: simple sniffer implementation
* Copyright (c) 2017 by Slavick Kuzmin
************************************/
#ifndef _SNIFFER_H_
#define _SNIFFER_H_

#include <pcap.h>
#include <stdlib.h> // for exit()

#include <arpa/inet.h> // for inet_ntoa()
#include <net/ethernet.h>
#include <netinet/ip.h>    //Provides declarations for ip header

#include "hash_table.h"
#include "vector.h"

#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/stat.h>

#define FILENAME "sniff.tmp"
#define INTERFACES "ifaces"

void packet_callback(u_char *, const struct pcap_pkthdr *, const u_char *);
void print_ip_packet  (const u_char* , int);
int show_ip_count(char* ip_str);
void start_analyse();
void stop_analyse();
void statis(char *line);
void select_iface(char* iface);
void help();
void createDaemon(char *dev);
void dieWithError(char *msg);
void createShMem();
void hdl(int sig);
void printhash();
void sh_ip();

struct sockaddr_in source;

struct sigaction act;

struct SPID {
  char dev[20];
  int pid;
};


pcap_t *handle; //Handle of the device that shall be sniffed
hashtable_t *hashtable;
vector v;
int i;

char *currDev;

#define BUFFER_SIZE 128
    key_t key;
	int fd, shmid, id, bufLen, buffer_written; 
	char *shm,buffer[BUFFER_SIZE], fifoBuffer[BUFFER_SIZE];;
	time_t rawtime;
	struct tm* timeinfo;


char errbuf[100] , *devname;

FILE *file, *flstat, *interfaces;


#endif //_SNIFFER_H_
