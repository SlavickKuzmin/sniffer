/***********************************
* file: hash_table.h
* written: 24/01/2017
* last modified: 26/01/2017
* synopsis: simple hash table for sniffer
* Copyright (c) 2017 by Slavick Kuzmin
************************************/
#ifndef HASH_TABLE_H_
#define HASH_TABLE_H_

#define _XOPEN_SOURCE 500 /* Enable certain library functions (strdup) on linux. */

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>

struct entry_s {
	char *key;
	char *value;
	struct entry_s *next;
};

typedef struct entry_s entry_t;

struct hashtable_s {
	int size;
	struct entry_s **table;
};

typedef struct hashtable_s hashtable_t;

/* Create a new hashtable. */
hashtable_t *ht_create( int size );
/* Hash a string for a particular hash table. */
int ht_hash( hashtable_t *hashtable, char *key );
/* Create a key-value pair. */
entry_t *ht_newpair( char *key, char *value );
/* Insert a key-value pair into a hash table. */
void ht_set( hashtable_t *hashtable, char *key, char *value );
/* Retrieve a key-value pair from a hash table and change packet cout. */
char *ht_get( hashtable_t *hashtable, char *key );
/* Retrieve a key-value pair from a hash table. */
void ht_add( hashtable_t *hashtable, char *key, char *value );

#endif //HASH_TABLE_H_
