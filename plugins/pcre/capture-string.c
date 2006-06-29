#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libprelude/prelude.h>
#include <libprelude/prelude-log.h>

#include "capture-string.h"

#define MAX_REF 64

typedef struct capture_elem {
        prelude_bool_t is_string;
        void *element;
} capture_elem_t;

struct capture_string {
        unsigned int index;
        capture_string_t *parent;
        capture_elem_t *elem[MAX_REF];
};


int capture_string_add_string(capture_string_t *capture, const char *string) 
{
        capture_elem_t *elem;
        
        if ( capture->index == MAX_REF )
                return -1;

        elem = malloc(sizeof(*elem));
        if ( ! elem )
                return -1;

        elem->is_string = TRUE;
        elem->element = strdup(string);
        
        prelude_log_debug(5, "capture[%u] = %s\n", capture->index, string);
        capture->elem[capture->index++] = elem;
        
        return 0;
}



int capture_string_new(capture_string_t *parent, capture_string_t **new) 
{
        capture_elem_t *elem;
        
        *new = malloc(sizeof(**new));
        if ( ! *new )
                return -1;

        (*new)->index = 0;
        (*new)->parent = parent;
        
        if ( parent ) {
                if ( parent->index == MAX_REF ) {
                        free(*new);
                        return -1;
                }
                
                elem = malloc(sizeof(*elem));
                if ( ! elem ) {
                        free(*new);
                        return -1;
                }

                elem->element = *new;
                elem->is_string = FALSE;
                parent->elem[parent->index++] = elem;
        }
        
        return 0;
}



capture_string_t *capture_string_get_parent(capture_string_t *cur)
{
        return cur->parent;
}



void *capture_string_get_element(capture_string_t *root, unsigned int index)
{
        if ( index >= root->index )
                return NULL;

        return root->elem[index]->element;
}



prelude_bool_t capture_string_is_element_string(capture_string_t *root, unsigned int index)
{
        return root->elem[index]->is_string;
}



void capture_string_destroy(capture_string_t *root)
{
        unsigned int i;

        for ( i = 0; i < root->index; i++ ) {
                if ( ! root->elem[i]->is_string )
                        capture_string_destroy(root->elem[i]->element);
                else
                        free(root->elem[i]->element);
                
                free(root->elem[i]);
        }

        free(root);
}



unsigned int capture_string_get_index(capture_string_t *root)
{
        return root->index;
}
