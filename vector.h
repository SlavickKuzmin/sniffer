/***********************************
* file: vector.h
* written: 24/01/2017
* last modified: 26/01/2017
* synopsis: simple vector implementation
* Copyright (c) 2017 by Slavick Kuzmin
************************************/
#ifndef VECTOR_H__
#define VECTOR_H__

typedef struct vector_ {
    void** data;
    int size;
    int count;
} vector;

void vector_init(vector*);
int vector_count(vector*);
void vector_add(vector*, void*);
void *vector_get(vector*, int);
void vector_free(vector*);

#endif
