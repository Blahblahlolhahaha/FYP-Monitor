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

/**
 * Initialises an array with a size and objects
 * @param array: A pointer to a array struct, should ensure that the array has not been initialised before
 * @param initSize: Initial size of array
 * @param objects: an array of object to initalise the array with. Should ensure that index 0 should contain initsize of array For eg: if init size is 1: objects should look like 
 * void *objects[] = {1,object 1} 
 * @param string: Whether if this array is gonna contain strings or not
 * @param size: Size of each element contained in array. Should use sizeof(type) for better results xD
 */
void initArray(struct Array* array,size_t initSize, void** objects,bool string,__uint32_t size);

/**
 * Appends a object to the array
 * @param array: pointer to array struct
 * @param object: object to add
 */
void push(struct Array* array,void* object);

/**
 * Appends multiple objects to the array
 * @param array: pointer to array struct
 * @param objects: array of objects to add to array.
 */
void pushObjects(struct Array* array,void** objects);

/**
 * Removes the object at specified index
 * @param array: pointer to array struct
 * @param index: index of object to remove. Note that the index used here will start from 1
 */
void removeIndex(struct Array* array, int index);

/**
 * Not working DO NOT USE
 */
void removeObject(struct Array* array, void* object);

/**
 * Frees up memory after use of the array
 */
void clearArray(struct Array* array);

#endif