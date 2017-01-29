/***********************************
* file: main.c
* written: 24/01/2017
* last modified: 26/01/2017
* synopsis: main file for simple ip sniffer application
* Copyright (c) 2017 by Slavick Kuzmin
************************************/
#include "sniffer.h"

int main(int argc, char **argv)
{
    hashtable  = ht_create(10000);
    vector_init(&v);

   /* act.sa_handler = hdl;
    sigset_t   set;
    sigemptyset(&set);                                                            
    sigaddset(&set, SIGUSR1);
    sigaddset(&set, SIGUSR2);
    act.sa_mask = set;
    sigaction(SIGUSR1, &act, 0);
    sigaction(SIGUSR2, &act, 0);*/
    
   sigemptyset(&act.sa_mask);
   act.sa_flags = 0;
   act.sa_handler = hdl;
   sigaction(SIGUSR1, &act, NULL);
   sigaction(SIGUSR2, &act, NULL);   
        // raise(SIGUSR1);
    
    if(argc < 2)
    {
        printf("Input error, use --help\n");
        exit(0);
    }
    if(strcmp(argv[1], "select")==0 && strcmp(argv[2], "iface")==0)
    {
        select_iface(argv[3]);
    } else if(strcmp(argv[1], "--help")==0)
    {
        help();
    } else if(strcmp(argv[1], "stat")==0)
    {
        if(argc >= 2)
        {
            pid_t pid;
            file = fopen(FILENAME, "r");
            fscanf(file, "%d", &pid);
            fclose(file);
            kill(pid, SIGUSR1);
           // statis(argv[2]);
        }
        else if(argc >= 1) {
            statis(NULL);
        }
    } else if(strcmp(argv[1], "stop")==0)
    {
        stop_analyse();
    } else if(strcmp(argv[1], "show")==0 && strcmp(argv[3], "count")==0)
    {
            pid_t pid;
            file = fopen(FILENAME, "r");
            fscanf(file, "%d", &pid);
            fclose(file);
            file = fopen("buf", "w");
            fprintf(file, "%s", argv[2]);
            fclose(file);
            kill(pid, SIGUSR2);
            
            
        //printf("IP: %s : %d\n", argv[2], show_ip_count(argv[2]));
    } else if(strcmp(argv[1], "start")==0)
    {
        start_analyse("");
    } else
    {
        printf("Input error, use --help\n");
        exit(0);
    }
    vector_free(&v);
    return 0;
}
 
