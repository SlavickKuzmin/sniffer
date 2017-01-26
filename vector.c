/***********************************
* file: vector.c
* written: 24/01/2017
* last modified: 26/01/2017
* synopsis: simple vector implementation
* Copyright (c) 2017 by Slavick Kuzmin
************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vector.h"

void vector_init(vector *v)
{
    v->data = NULL;
    v->size = 0;
    v->count = 0;
}

int vector_count(vector *v)
{
    return v->count;
}

void vector_add(vector *v, void *e)
{
    if (v->size == 0) {
        v->size = 10;
        v->data = malloc(sizeof(void*) * v->size);
        memset(v->data, '\0', sizeof(void*) * v->size);
    }

    if (v->size == v->count) {
        v->size *= 2;
        v->data = realloc(v->data, sizeof(void*) * v->size);
    }

    v->data[v->count] = e;
    v->count++;
}
void *vector_get(vector *v, int index)
{
    if (index >= v->count) {
        return NULL;
    }

    return v->data[index];
}

void vector_free(vector *v)
{
    free(v->data);
}
