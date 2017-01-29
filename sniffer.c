/***********************************
* file: sniffer.c
* written: 24/01/2017
* last modified: 26/01/2017
* synopsis: simple sniffer implementation
* Copyright (c) 2017 by Slavick Kuzmin
************************************/
#include "sniffer.h"

void packet_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    int size = header->len;  //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));

    if(iph->protocol == 6) //Check the Protocol and do accordingly...
            print_ip_packet(buffer , size);

}
 
void print_ip_packet(const u_char * Buffer, int Size)
{
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
    iphdrlen =iph->ihl*4;

    char bool = 0;
    
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    for (i = 0; i < vector_count(&v); i++) {
        if(strcmp(inet_ntoa(source.sin_addr),(char*)vector_get(&v, i)) == 0)
        {
            bool = 1;
            break;
        }
        bool = 0;
    }

    if(bool == 0) {
    int size = strlen(inet_ntoa(source.sin_addr));
    char *str = (char*)malloc(size*sizeof(char));
    strcpy(str, inet_ntoa(source.sin_addr));
    vector_add(&v, str);
    }

    ht_set(hashtable, inet_ntoa(source.sin_addr), "1");

    fseek(flstat, SEEK_SET, 0);
   // fflush(stdout);
   // printf("vector size=%d \n", vector_count(&v));
   // fflush(stdout);
    for(i=0; i < vector_count(&v); i++)
        fprintf(flstat, "%s %s\n", (char*)vector_get(&v, i), ht_get(hashtable, (char*)vector_get(&v, i)) );
}

int show_ip_count(char* ip_str)
{
    char fname[20];
    char ip[15];
    char count[15];

    interfaces = fopen(INTERFACES, "r");
    while(1)
    {
        fscanf(interfaces, "%s", fname);
        if(!feof(interfaces))
        {
            flstat = fopen(fname, "r");
            if(flstat == NULL) {
                printf("Can't open file: %s. Program stopped.\n", fname);
                exit(1);
            }
            while(1)
            {
                fscanf(flstat, "%s", ip);
                fscanf(flstat, "%s", count);
                if(!feof(flstat))
                    ht_add(hashtable, ip, count);
                else
                    break;
            }
        }
        else break;
    }
    fclose(flstat);
    fclose(interfaces);

 return atoi(ht_get(hashtable, ip_str));   
}
void start_analyse()
{
    createDaemon("eth0");

    char name[10];
    int fl=1;

    flstat = fopen("eth0", "w");
    interfaces = fopen(INTERFACES, "a+");

    while(!feof(interfaces))
    {
        if(strcmp(name, "eth0")==0) { fl = 0 ; break; }
        else fl = 1;
        fscanf(interfaces, "%s", name);
    }

    if(fl == 1) {
        fseek(interfaces, SEEK_END, 1);
        fprintf(interfaces, "%s ", "eth0");
    }
    fclose(interfaces);

    flstat = fopen("eth0", "w");
    if(flstat == NULL)
    {
        printf("Can't open file: %s\n", flstat);
        exit(1);
    }
    
    devname = "eth0";

    printf("Opening device %s for sniffing ... Done.(Use cmd: stop - for end sniffing)\n" , devname);    //Open the device for sniffing
    handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);
    if (handle == NULL) 
    {
        fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf);
        exit(1);
    }
    printf(" ");
    pcap_loop(handle , -1 , packet_callback , NULL);    //Put the device in sniff loop
}

void stop_analyse()
{
    pid_t pid;
   /* file = fopen(FILENAME, "r");
    fscanf(file, "%d", &pid);
    fclose(file);
    file = fopen(FILENAME, "w");
    fprintf(file, "%d", -1);
    fclose(file);
    if(pid == -1)
    {
        printf("Error, program not run! Use ./sniff start\n");
        exit(1);
    }
    kill(pid, SIGKILL);
    printf("Prorgam stopped.\n");*/
    file = fopen("pids", "a+b");
    if(file == NULL) printf("pids error\n");
        printf("Ok1\n");
    struct SPID spid;
    
    fread(&spid, 1, sizeof(struct SPID), file);
    
    if(feof(file)) {printf("error!\n"); exit(1);}
    printf("Ok2\n");
     vector tmp;
     vector_init(&tmp);
    while(1)
    {
        if(feof(file)) break;
        
        pid = spid.pid;
        vector_add(&tmp, spid.dev);
        if(pid != -1)
        printf("I want kill pid: %d\n", pid);
        if(pid != -1)
        kill(pid, SIGKILL);
        else printf("program not runs\n");
        fread(&spid, 1, sizeof(struct SPID), file);
    }

    fclose(file);
    file = fopen("pids", "wb");
    int i;
    for(i=0;i < vector_count(&tmp);i++)
    {
        strcpy(spid.dev,vector_get(&tmp, i));
        spid.pid = -1;
        fwrite(&spid, 1, sizeof(struct SPID), file);
    }
    vector_free(&tmp);
    fclose(file);
}
void select_iface(char* iface)
{

    createDaemon(iface);
    createShMem();
    
    char name[10];
    int fl=1;

    flstat = fopen(iface, "w");
    interfaces = fopen(INTERFACES, "a+");

    while(!feof(interfaces))
    {
        if(strcmp(name, iface)==0) { fl = 0 ; break; }
        else fl = 1;
        fscanf(interfaces, "%s", name);
    }

    if(fl == 1) {
        fseek(interfaces, SEEK_END, 1);
        fprintf(interfaces, "%s ", iface);
    }
    fclose(interfaces);

    devname = iface;

    printf("Opening device %s for sniffing ... Done.(Use cmd: stop - for end sniffing)\n" , devname);    //Open the device for sniffing
    fflush(stdout);
    fflush(stdin);
    handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);
    if (handle == NULL) 
    {
        fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf);
        exit(1);
    }
    printf(" ");
    pcap_loop(handle , -1 , packet_callback , NULL);    //Put the device in sniff loop
}
void help()
{
    printf("Use command:\n");
    printf("start\n\t-(packets are being sniffed from now on from default iface(eth0))\n");
    printf("stop\n\t-(packets are not sniffed)\n");
    printf("show [ip] count\n\t-(print number of packets received from ip address)\n");
    printf("select iface [iface]\n\t- (select interface for sniffing eth0, wlan0, ethN, wlanN...)\n");
    printf("stat [iface]\n\t- show all collected statistics for particular interface, if iface omitted - for all interfaces.\n");
    printf("--help\n\t- (show usage information)\n");
}
void createDaemon(char *dev)
{
    pid_t process_id = 0;
    pid_t sid = 0;
    
    char name[10];
    int pid;
    int fl=1;
    
    //memcpy(currDev,dev, strlen(dev)*sizeof(char));

    currDev = strdup(dev);

    /*file = fopen(FILENAME, "r");
    if(file == NULL)
    {
     file = fopen(FILENAME, "w");
     fprintf(file, "%d", -1);
     fclose(file);
     file = fopen(FILENAME, "r");
    }
    
    fscanf(file, "%d", &sid);
    fclose(file);
    
    if(sid != -1){
        printf("Error! Program already exist. Use ./sniff stop.\n");
        exit(1);
    }
*/
    printf("Create daemon ... \n");
    process_id = fork();    // Create child process

    if (process_id < 0) // Indication of fork() failure
    {
        printf("fork failed!\n");
        exit(1);// Return failure in exit status
    }
    if (process_id > 0)// PARENT PROCESS. Need to kill it.
    {
        exit(0);// return success in exit status
    }
    sid = setsid();//set new session
    if(sid < 0)
    {
        exit(1);// Return failure
    }
    printf("Process ID: %d\n", sid);
   /* file = fopen(FILENAME, "w");
    fprintf(file, "%d\n", sid);
    fclose(file);*/

    struct SPID spid;
   
    file = fopen("pids", "a+b");
    if(file == NULL) printf("error!\n");
   

   
    fread(&spid, 1, sizeof(struct SPID), file);
    printf("1\n");
    int steps=0;
    int flg = 1;
    if(feof(file)){
    printf("2\n");
        fseek(file, 0, SEEK_SET);
     strcpy(spid.dev,dev);
     spid.pid = sid;
     fwrite(&spid, 1, sizeof(struct SPID), file);
    }
    else
    {
        printf("3\n");
        while(1)
        {
            printf("4\n");
            steps++;
         if(strcmp(spid.dev, dev)==0)
         {
             printf("5\n");
         flg = 0;
         if(spid.pid != -1) {printf("exec\n"); exit(0);}
         int i;
         fclose(file);
         printf("6\n");
         file = fopen("pids", "w+b");
         for(i=0;i<steps-1;i++)
             fread(&spid, 1, sizeof(struct SPID), file);
         strcpy(spid.dev, dev);
         spid.pid = sid;
         fwrite(&spid, 1, sizeof(struct SPID), file);
         break;
         }
         fread(&spid, 1, sizeof(struct SPID), file);
         if(feof(file)) break;
        }
        printf("7\n");
        if(flg == 1){
        printf("Im tyt\n");
        fseek(file, 0, SEEK_END);
        strcpy(spid.dev,dev);
        spid.pid = sid;
        printf("write %s:  %d\n", spid.dev, spid.pid);
        fwrite(&spid, 1, sizeof(struct SPID), file);
        }
    }
    fclose(file);
    
    printf("Done.\n");
}

void statis(char *line)
{
    char ip[15];
    char count[15];
    char fname[50];

    if(line == NULL)
    {
        interfaces = fopen(INTERFACES, "r");
        if(interfaces == NULL) {
            printf("Can't open file: %s. Program stopped.\n", INTERFACES);
            exit(1);
        }
        while(1)
        {
            fscanf(interfaces, "%s", fname);
            if(!feof(interfaces))
            {
            flstat = fopen(fname, "r");
            if(flstat == NULL) {
                printf("Can't open file: %s. Program stopped.\n", fname);
                exit(1);
            }
            printf("Interface :%s\n", fname);
            while(1)
            {
                fscanf(flstat, "%s", ip);
                fscanf(flstat, "%s", count);
                if(!feof(flstat))
                    printf("IP: %s :\t%s packets.\n", ip, count);
                else
                    break;
            }
            }
            else break;
            fclose(flstat);
        }
        fclose(interfaces);
    }
    else
    {
     /*   flstat = fopen(line, "r");
        if(flstat == NULL) {
            printf("Can't open file: %s. Program stopped.\n", line);
            exit(1);
        }
        while(1)
        {
            fscanf(flstat, "%s", ip);
            fscanf(flstat, "%s", count);
            if(!feof(flstat))
            printf("IP: %s :\t%s packets.\n", ip, count);
            else
                break;
        }
        */
     	if ((fd = open("sharFile", O_RDONLY)) < 0)
		dieWithError("open() failed");
	
        while (read(fd, fifoBuffer, BUFFER_SIZE) > 0)
		printf("%s", fifoBuffer);
    }
}
void hdl(int sig)
{
        printf("\n");
        
        char *signal;
        if(sig == SIGUSR1)
        {
            printf("Im breakloop... %d", handle);
            //pcap_breakloop(handle);
            printf("Done.\n");
            int i;
            for(i=0;i<10;i++)
               printf("SIGUSR1\n");
            printf("My Process ID: %d\n", getpid());
            
            printhash();
            
           // handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);
           // pcap_loop(handle , -1 , packet_callback , NULL);    //Put the device in sniff loop
        }
        else if(sig == SIGUSR2)
        {
            printf("Im breakloop... %d", handle);
            //pcap_breakloop(handle);
            printf("Done.\n");
            int i;
            for(i=0;i<10;i++)
               printf("SIGUSR1\n");
            printf("My Process ID: %d\n", getpid());
            
            sh_ip();
        }
        else
               printf("Something else\n");
               
}
void dieWithError(char *msg)
{
	printf("[-]ERROR: %s\n");
	exit(0);
}
void createShMem()
{
   // printf("Creating fifo...\n");

	//create FIFO
//	if ((mkfifo("sharFile" , 0744)) < 0)
//		dieWithError("mkfifo() failed\n");
//else printf("Done.\n");

//	if ((fd = open("sharFile", O_WRONLY)) < 0)
//		dieWithError("open() failed");
//    printf("Done.\n");
//    fflush(stdout);
//    fflush(stdin);
}
void printhash(){
    int i;
    
    printf("pid =%d vector size=%d\n",getpid(), vector_count(&v));
       for(i=0; i < vector_count(&v); i++)
        printf("%s %s\n", (char*)vector_get(&v, i), ht_get(hashtable, (char*)vector_get(&v, i)) );
}

void sh_ip()
{
 char ips[15];
 file = fopen("buf", "r");
 fscanf(file, "%s", ips);
 fclose(file);
 printf("IP: %s : %s\n", ips, ht_get(hashtable, (char*)ips));   
}
