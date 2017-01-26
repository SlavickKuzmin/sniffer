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

    fseek(fstat, SEEK_SET, 0);
    for(i=0; i < vector_count(&v); i++)
        fprintf(fstat, "%s %s\n", (char*)vector_get(&v, i), ht_get(hashtable, (char*)vector_get(&v, i)) );
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
            fstat = fopen(fname, "r");
            if(fstat == NULL) {
                printf("Can't open file: %s. Program stopped.\n", fname);
                exit(1);
            }
            while(1)
            {
                fscanf(fstat, "%s", ip);
                fscanf(fstat, "%s", count);
                if(!feof(fstat))
                    ht_add(hashtable, ip, count);
                else
                    break;
            }
        }
        else break;
    }
    fclose(fstat);
    fclose(interfaces);

 return atoi(ht_get(hashtable, ip_str));   
}
void start_analyse()
{
    createDaemon();

    char name[10];
    int fl=1;

    fstat = fopen("eth0", "w");
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

    fstat = fopen("eth0", "w");
    if(fstat == NULL)
    {
        printf("Can't open file: %s\n", fstat);
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
    file = fopen(FILENAME, "r");
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
    printf("Prorgam stopped.\n");
}
void select_iface(char* iface)
{

    createDaemon();

    char name[10];
    int fl=1;

    fstat = fopen(iface, "w");
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
    pcap_t *handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);
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
void createDaemon()
{
    pid_t process_id = 0;
    pid_t sid = 0;

    file = fopen(FILENAME, "r");
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

    file = fopen(FILENAME, "w");
    fprintf(file, "%d\n", sid);
    fclose(file);
}

void stat(char *line)
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
            fstat = fopen(fname, "r");
            if(fstat == NULL) {
                printf("Can't open file: %s. Program stopped.\n", fname);
                exit(1);
            }
            printf("Interface :%s\n", fname);
            while(1)
            {
                fscanf(fstat, "%s", ip);
                fscanf(fstat, "%s", count);
                if(!feof(fstat))
                    printf("IP: %s :\t%s packets.\n", ip, count);
                else
                    break;
            }
            }
            else break;
            fclose(fstat);
        }
        fclose(interfaces);
    }
    else
    {
        fstat = fopen(line, "r");
        if(fstat == NULL) {
            printf("Can't open file: %s. Program stopped.\n", line);
            exit(1);
        }
        while(1)
        {
            fscanf(fstat, "%s", ip);
            fscanf(fstat, "%s", count);
            if(!feof(fstat))
            printf("IP: %s :\t%s packets.\n", ip, count);
            else
                break;
        }
    }
}
