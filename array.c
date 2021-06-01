#include "include/array.h"
#include "assert.h"
#include <string.h>




void initArray(struct Array* array,size_t initSize, void** objects,bool string,__uint32_t size){
    array->itemSize = size;
    if(size !=0){
        array->string = string;
        array->array = malloc(initSize *  __SIZEOF_POINTER__ + sizeof(int));
        if(array->array){
            array->size = initSize;
            int objectSize = (int)(void*)objects[0];
            array->array[0]  = objectSize;
            for(int i=0;i<objectSize;i++){
                void* test = malloc(size);
                if(test){
                    (array)->array[i + 1] = test;
                    if(array->string){
                        strcpy(array->array[i+1],objects[i+1]);
                    }
                    else{
                        memcpy(array->array[i+1],objects[i+1],array->itemSize);
                    }
                }
                
            }
        }
    } 
}

void push(struct Array* array,void* object){
    int newUsed = array->array[0] + 1;
    void** pointer;
    if( newUsed > array->size){
        array->size = newUsed;
        pointer = reallocarray(array->array,array->size,(array->size+1)* __SIZEOF_POINTER__);
        if(pointer){
            array->array = pointer;
            array->array[0] += 1;
            int index = array->array[0];
            array->array[index] = malloc(array->itemSize);
            if(array->array[index]){
                if(array->string){
                    strcpy(array->array[index],object);
                }
                else{
                    memcpy(array->array[index],object,array->itemSize);
                }
            }
        }
        else{
            printf("Failed to allocate space.... exiting");
            free(pointer);
            exit(0);
        }
    }
    else{
        array->array[0] += 1;
        int index = array->array[0];
        array->array[index] = malloc(array->itemSize);
        
        if(array->array[index]){
            strcpy(array->array[index],object);
        }
    }
}


void pushObjects(struct Array* array,void** objects){
    int objectSize = objects[0];
    int newUsed = array->array[0] + objectSize;
    void** pointer;
    if( newUsed > array->size){
        array->size = newUsed;
        pointer = reallocarray(array->array,array->array[0],array->size);
        if(pointer){
            array->array = pointer;
            for(int i=0;i<objectSize;i++){
                array->array[0] += 1;
                int index = array->array[0];
                void *test = malloc(array->itemSize);
                if(test){
                    array->array[index] = test;
                    if(array->string){
                        strcpy(array->array[index],objects[i+1]);
                    }
                    else{
                        memcpy(array->array[index],objects[i+1],array->itemSize);
                    }
                    
                }
                
            }
        }
        else{
            printf("Failed to allocate space.... exiting");
            free(pointer);
            exit(0);
        }
    }
    else{
        for(int i=0;i<objectSize;i++){
            array->array[0] += 1;
            int index = array->array[0];
            void *test = malloc(array->itemSize);
            if(test){
                array->array[index] = test;
                if(array->string){
                    strcpy(array->array[index],objects[i+1]);
                }
                else{
                    memcpy(array->array[index],objects[i+1],array->itemSize);
                }
            }
        }
    }
}

void removeIndex(struct Array* array, int index){
    int newUsed = array->array[0] - 1;
    void** pointer = malloc(newUsed * __SIZEOF_POINTER__ + sizeof(int));
    bool skipped = false;
    if(pointer){
        for(int i = 1; i<= newUsed + 1; i++){
            if(!skipped & i - 1== index){
                skipped = true;
                continue;
            }
            void *test = malloc(array->itemSize);
            if(test){
                pointer[skipped? i - 1 : i] = test;
                if(array->string){
                    strcpy(pointer[skipped? i - 1 : i],array->array[i]);
                }
                else{
                    memcpy(pointer[skipped? i - 1 : i],array->array[i],array->itemSize);
                }
            }
        }
        pointer[0] = array->array[0] - 1;
        array->array = pointer;
        
    }
    else{
        printf("Failed to allocate space.... exiting");
        free(pointer);
        exit(0);
    }
}

// void removeObject(struct Array* array, void* object){
//     int newUsed = array->used - 1;
//     int* pointer = malloc(newUsed);
//     bool skipped = false;
//     Type type = array->type;
//     if(pointer){
//         for(int i = 0; i< newUsed; i++){
//             bool isSame = same(array->type,(void*)array->array[i] , object);
//             if(!skipped && isSame){
//                 skipped = true;
//                 continue;
//             }
//             pointer[skipped? i - 1 : i] = malloc(array->itemSize);
//             pointer[skipped? i - 1 : i] = array->array[i];
//         }
//         pointer[0] = array->array[0] - 1;
//         array->array = pointer;
//         array->used -=1;
//     }
//     else{
//         printf("Failed to allocate space.... exiting");
//         free(pointer);
//         exit(0);
//     }   
// }

void clearArray(struct Array* array){
    free(array->array);
    array->array = NULL;
    array->size = 0;
}