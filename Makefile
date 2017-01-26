#/***********************************
#* file: Makefile
#* written: 24/01/2017
#* last modified: 26/01/2017
#* Copyright (c) 2017 by Slavick Kuzmin
#************************************/

CC=gcc
CFLAGS=-c
LPCAP=-lpcap
SOURCES=main.c vector.c  hash_table.c  sniffer.c 
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=sniff

all: $(SOURCES) $(LPCAP) $(EXECUTABLE)
	
$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(LPCAP) $(OBJECTS) -o $@

.c.o:
	$(CC) $(CFLAGS) $< -o $@
clean:
	rm -rf *.o sniff
