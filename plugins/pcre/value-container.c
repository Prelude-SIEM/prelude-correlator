/*****
*
* Copyright (C) 2006 PreludeIDS Technologies. All Rights Reserved.
* Author: Yoann Vandoorselaere <yoann.v@prelude-ids.com>
*
* This file is part of the Prelude-LML program.
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by 
* the Free Software Foundation; either version 2, or (at your option)
* any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; see the file COPYING.  If not, write to
* the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
*
*****/

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <pcre.h>

#include <libprelude/prelude.h>
#include <libprelude/prelude-string.h>
#include <libprelude/prelude-log.h>

#include "prelude-correlator.h"
#include "pcre-mod.h"
#include "value-container.h"


struct value_container {
        prelude_list_t list;
        prelude_list_t value_item_list;
        void *data;
};


typedef struct {
        prelude_list_t list;
        int refno;
        char *value;
} value_item_t;



static int add_dynamic_object_value(value_container_t *vcont, unsigned int reference)
{
        value_item_t *vitem;

        if ( reference >= MAX_REFERENCE_PER_RULE ) {
                prelude_log(PRELUDE_LOG_WARN, "reference number %d is too high.\n", reference);
                return -1;
        }

        vitem = malloc(sizeof(*vitem));
        if ( ! vitem ) {
                prelude_log(PRELUDE_LOG_ERR, "memory exhausted.\n");
                return -1;
        }
        
        vitem->value = NULL;
        vitem->refno = reference;
        prelude_list_add_tail(&vcont->value_item_list, &vitem->list);

        return 0;                
}



static int add_fixed_object_value(value_container_t *vcont, prelude_string_t *buf)
{
        int ret;
        value_item_t *vitem;

        vitem = malloc(sizeof(*vitem));
        if ( ! vitem ) {
                prelude_log(PRELUDE_LOG_ERR, "memory exhausted.\n");
                return -1;
        }

        ret = prelude_string_get_string_released(buf, &vitem->value);
        if ( ret < 0 ) {
                prelude_perror(ret, "error getting released string");
                free(vitem);
                return -1;
        }

        vitem->refno = -1;
        prelude_list_add_tail(&vcont->value_item_list, &vitem->list);

        return 0;
}



static int parse_value(value_container_t *vcont, const char *line)
{
        int i, ret;
        char num[10];
        const char *str;
        prelude_string_t *strbuf;

        str = line;

        while ( *str ) {
                if ( *str == '$' && *(str + 1) != '$' ) {

                        i = 0;
                        str++;
                        
                        while ( isdigit((int) *str) && i < sizeof(num) )
                                num[i++] = *str++;

                        if ( ! i )
                                return -1;

                        num[i] = 0;

                        if ( add_dynamic_object_value(vcont, atoi(num)) < 0 )
                                return -1;

                        continue;
                }

                ret = prelude_string_new(&strbuf);
                if ( ret < 0 ) {
                        prelude_perror(ret, "error creating new prelude-string");
                        return -1;
                }

                while ( *str ) {
                        if ( *str == '$' ) {
                                if ( *(str + 1) == '$' )
                                        str++;
                                else
                                        break;
                        }

                        if ( prelude_string_ncat(strbuf, str, 1) < 0 )
                                return -1;
                        str++;
                }

                if ( add_fixed_object_value(vcont, strbuf) < 0 )
                        return -1;

                prelude_string_destroy(strbuf);
        }

        return 0;
}



static void resolve_referenced_value(prelude_string_t *outstr, value_item_t *vitem, char **capture, size_t capture_size)
{
        if ( (vitem->refno - 1) < 0 || (vitem->refno - 1) >= capture_size ) {
                prelude_log(PRELUDE_LOG_ERR, "Invalid reference: %d (max is %lu).\n", vitem->refno, capture_size);
                return;
        }
        
        if ( capture[vitem->refno - 1] )
                prelude_string_cat(outstr, capture[vitem->refno - 1]);
}



prelude_string_t *value_container_resolve(value_container_t *vcont, const pcre_rule_t *rule,
                                          char **capture, size_t capture_size)
{
        int ret;
        value_item_t *vitem;
        prelude_list_t *tmp;
        prelude_string_t *str;
        
        ret = prelude_string_new(&str);
        if ( ret < 0 ) {
                prelude_perror(ret, "error creating prelude-string");
                return NULL;
        }

        prelude_list_for_each(&vcont->value_item_list, tmp) {
                vitem = prelude_list_entry(tmp, value_item_t, list);
                
                if ( vitem->refno != -1 )
                        resolve_referenced_value(str, vitem, capture, capture_size);
                
                else if ( prelude_string_cat(str, vitem->value) < 0 ) {
                        prelude_string_destroy(str);
                        return NULL;
                }
        }

        if ( prelude_string_is_empty(str) ) {
                prelude_string_destroy(str);
                return NULL;
        }
        
        return str;
}



int value_container_new(value_container_t **vcont, const char *str)
{
        int ret;
        
        *vcont = malloc(sizeof(**vcont));
        if ( ! *vcont ) {
                prelude_log(PRELUDE_LOG_ERR, "memory exhausted.\n");
                return -1;
        }

        (*vcont)->data = NULL;
        prelude_list_init(&(*vcont)->value_item_list);
        
        ret = parse_value(*vcont, str);
        if ( ret < 0 ) {
                free(*vcont);
                return ret;
        }

        return 0;
}



void value_container_destroy(value_container_t *vcont)
{
        value_item_t *vitem;
        prelude_list_t *tmp, *bkp;
        
        prelude_list_for_each_safe(&vcont->value_item_list, tmp, bkp) {
                vitem = prelude_list_entry(tmp, value_item_t, list);

                if ( vitem->value )
                        free(vitem->value);
                
                prelude_list_del(&vitem->list);
                free(vitem);
        }

        free(vcont);
}



void value_container_reset(value_container_t *vcont)
{
        value_item_t *vitem;
        prelude_list_t *tmp;
        
        prelude_list_for_each(&vcont->value_item_list, tmp) {
                vitem = prelude_list_entry(tmp, value_item_t, list);

                if ( vitem->refno != -1 && vitem->value ) {
                        free(vitem->value);
                        vitem->value = NULL;
                }
        }
}



void *value_container_get_data(value_container_t *vcont)
{
        return vcont->data;
}


void value_container_set_data(value_container_t *vcont, void *data)
{
        vcont->data = data;
}
