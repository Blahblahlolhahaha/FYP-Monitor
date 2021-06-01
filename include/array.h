#pragma once

#ifndef ARRAY_H
#define ARRAY_H

#include <stdio.h>
#include <malloc.h>
#include <stdbool.h>
#include <stdlib.h>


typedef enum{
    INT,DOUBLE,LONG,FLOAT,CHAR,STRING,VOID
}Type;

struct Array {
    void** array;
    size_t size;
    __uint32_t itemSize;
    bool string;
};



void initArray(struct Array* array,size_t initSize, void** objects,bool string,__uint32_t size);

void push(struct Array* array,void* object);

void pushObjects(struct Array* array,void** objects);

void removeIndex(struct Array* array, int index);

void removeObject(struct Array* array, void* object);

void clearArray(struct Array* array);

#endif