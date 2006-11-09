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
#include <assert.h>

#include <libprelude/prelude.h>
#include <libprelude/prelude-string.h>
#include <libprelude/prelude-log.h>

#include "prelude-correlator.h"
#include "pcre-mod.h"
#include "pcre-context.h"
#include "value-container.h"


struct value_container {
        prelude_list_t list;
        prelude_list_t value_item_list;
        void *data;
};


typedef enum {
        VALUE_ITEM_FIXED     = 0,
        VALUE_ITEM_CONTEXT   = 1,
        VALUE_ITEM_REFERENCE = 2
} prelude_value_item_type_t;


typedef struct {
        prelude_list_t list;
        prelude_value_item_type_t type;
} value_item_t;

typedef struct {
        prelude_list_t list;
        prelude_value_item_type_t type;

        value_container_t *context;
} value_item_context_t;

typedef struct {
        prelude_list_t list;
        prelude_value_item_type_t type;
        
        char *value;
} value_item_fixed_t;

typedef struct {
        prelude_list_t list;
        prelude_value_item_type_t type;

        int refno;
        
        prelude_bool_t multiple_value;
        value_container_t *list_index;
        
} value_item_reference_t;



static int add_context_value(value_container_t *vcont, const char *context)
{
        int ret;
        value_container_t *sub;
        value_item_context_t *vitem;

        printf("add ctx value %s\n", context);
        
        ret = value_container_new(&sub, context);
        if ( ret < 0 )
                return ret;
        
        vitem = malloc(sizeof(*vitem));
        if ( ! vitem ) {
                value_container_destroy(sub);
                prelude_log(PRELUDE_LOG_ERR, "memory exhausted.\n");
                return -1;
        }

        vitem->context = sub;
        vitem->type = VALUE_ITEM_CONTEXT;
        
        prelude_list_add_tail(&vcont->value_item_list, &vitem->list);

        return 0;                
}



static int add_reference_value(value_container_t *vcont,
                               unsigned int reference, prelude_string_t *lindex, prelude_bool_t multiple)
{
        int ret;
        value_item_reference_t *vitem;
        
        if ( reference >= MAX_REFERENCE_PER_RULE ) {
                prelude_log(PRELUDE_LOG_WARN, "reference number %d is too high.\n", reference);
                return -1;
        }

        vitem = malloc(sizeof(*vitem));
        if ( ! vitem ) {
                prelude_log(PRELUDE_LOG_ERR, "memory exhausted.\n");
                return -1;
        }

        if ( ! lindex )
                vitem->list_index = NULL;
        else{
                ret = value_container_new(&vitem->list_index, prelude_string_get_string(lindex));
                if ( ret < 0 ) {
                        free(vitem);
                        return ret;
                }
        }
        
        vitem->refno = reference;
        vitem->multiple_value = multiple;
        vitem->type = VALUE_ITEM_REFERENCE;
        
        prelude_list_add_tail(&vcont->value_item_list, &vitem->list);

        return 0;                
}



static int add_fixed_value(value_container_t *vcont, prelude_string_t *buf)
{
        int ret;
        value_item_fixed_t *vitem;

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
        
        vitem->type = VALUE_ITEM_FIXED;
        prelude_list_add_tail(&vcont->value_item_list, &vitem->list);

        return 0;
}



static int parse_context(const char **str, char **ctx)
{
        int ret;
        prelude_string_t *out;
        unsigned int keep_going = 0;
        
        ret = prelude_string_new(&out);
        if ( ret < 0 )
                return ret;
        
        while ( **str && ! isspace(**str) /*|| keep_going */ ) {                
                if ( **str == '(' ) {
                        if ( keep_going++ == 0 ) {
                                (*str)++;
                                continue;
                        }
                }

                if ( **str == ')' && --keep_going == 0 ) {
                        (*str)++;
                        break;
                }
                
                prelude_string_ncat(out, (*str)++, 1);
        }

        if ( keep_going )
                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "missing closure parenthesis");
        
        ret = prelude_string_get_string_released(out, ctx);
        prelude_string_destroy(out);
        
        return ret;
}



static int parse_variable(const char **str, int *reference, prelude_string_t **lindex, prelude_bool_t *multiple) 
{
        char *eptr;

        *lindex = NULL;
        *multiple = FALSE;
        
        *reference = strtoul(*str, &eptr, 10);
        if ( eptr == *str )
                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "Invalid reference '%s'", *str);

        *str = eptr;
        if ( *eptr != '[' )
                return 0;

        if ( *++(*str) != '*' ) {
                prelude_string_new(lindex);
                while ( **str != ']' )
                        prelude_string_ncat(*lindex, (*str)++, 1);
        } else {
                *multiple = TRUE;
                (*str)++;
        }
       
        if ( **str != ']' )
                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "Missing closure bracket");

        (*str)++;
        
        return 0;
}



static int add_fixed_value_if_needed(value_container_t *vcont, prelude_string_t *buf)
{
        int ret;
        
        if ( prelude_string_is_empty(buf) )
                return 0;

        ret = add_fixed_value(vcont, buf);
        prelude_string_clear(buf);

        return ret;
}


static int parse_value(value_container_t *vcont, const char *line)
{
        prelude_string_t *buf;
        int ret, reference = 0;
        prelude_string_t *lindex;
        prelude_bool_t escaped = FALSE, multiple = FALSE;
        
        ret = prelude_string_new(&buf);
        if ( ret < 0 )
                return ret;

        while ( *line ) {
                if ( *line == '\\' && ! escaped ) {
                        escaped = TRUE;
                        line++;
                }
                
                else if ( ! escaped && *line == '$' ) {
                        if ( add_fixed_value_if_needed(vcont, buf) < 0 )
                                goto err;

                        line++;
                        
                        if ( isdigit(*line) ) {
                                lindex = NULL;
                                
                                ret = parse_variable(&line, &reference, &lindex, &multiple);
                                if ( ret < 0 )
                                        goto err;

                                if ( add_reference_value(vcont, reference, lindex, multiple) < 0 )
                                        goto err;

                                if ( lindex )
                                        prelude_string_destroy(lindex);
                                
                        } else {
                                char *context;
                                
                                ret = parse_context(&line, &context);
                                if ( ret < 0 )
                                        goto err;

                                ret = add_context_value(vcont, context);
                                free(context);
                                
                                if ( ret < 0 )
                                        goto err;
                        }
                }

                else {                        
                        prelude_string_ncat(buf, line++, 1);
                        escaped = FALSE;
                }
        }
        
        ret = add_fixed_value_if_needed(vcont, buf);
        
 err:
        prelude_string_destroy(buf);
        return ret;
}


static int propagate_string(prelude_list_t *outlist, const char *str)
{
        int ret;
        prelude_list_t *tmp;
        prelude_string_t *base;

        if ( prelude_list_is_empty(outlist) ) {
                ret = prelude_string_new_dup(&base, str);
                if ( ret < 0 )
                        return ret;
                
                prelude_linked_object_add_tail(outlist, (prelude_linked_object_t *) base);
                return 0;
        }
        
        prelude_list_for_each(outlist, tmp) {
                base = prelude_linked_object_get_object(tmp);

                ret = prelude_string_cat(base, str);
                if ( ret < 0 )
                        return ret;
        }

        return 0;
}



static int multidimensional_capture_with_index(prelude_list_t *outlist, value_item_reference_t *vitem,
                                               pcre_plugin_t *plugin, const pcre_rule_t *rule, capture_string_t *capture)
{
        prelude_string_t *str;
        unsigned int index;
        int lindex;
        
        str = value_container_resolve(vitem->list_index, plugin, rule, capture);
        if ( ! str )
                return -1;

        lindex = strtol(prelude_string_get_string(str), NULL, 10);
                        
        index = capture_string_get_index(capture);
        assert(lindex < 0 || lindex < index);

        prelude_string_clear(str);
        prelude_string_cat(str, capture_string_get_element(capture, lindex));
        
        if ( ! prelude_string_is_empty(str) )
                propagate_string(outlist, prelude_string_get_string(str));

        prelude_string_destroy(str);
        
        return 0;
}



static int multidimensional_capture_to_flat_string(prelude_list_t *outlist,
                                                   value_item_reference_t *vitem, capture_string_t *capture)
{
        int ret;
        unsigned int index, i;
        prelude_string_t *str;

        ret = prelude_string_new(&str);
        if ( ret < 0 )
                return ret;
        
        index = capture_string_get_index(capture);
        
        for ( i = 0; i < index; i++ ) {
                void *sub = capture_string_get_element(capture, i);

                /*
                 * As of now, the list should be flat
                 */
                assert(capture_string_is_element_string(capture, i));

                prelude_string_cat(str, sub);        
                if ( i + 1 < index )
                        prelude_string_cat(str, ",");
        }

        if ( ! prelude_string_is_empty(str) )
                propagate_string(outlist, prelude_string_get_string(str));
        
        prelude_string_destroy(str);

        return 0;
}



static inline void __list_splice(prelude_list_t *head, prelude_list_t *added)
{
        prelude_list_t *first = added->next;
        prelude_list_t *last = added->prev;
        prelude_list_t *at = head->next;

        first->prev = head;
        head->next = first;

        last->next = at;
        at->prev = last;
}


/**
 * list_splice - join two lists
 * @list: the new list to add.
 * @head: the place to add it in the first list.
 */
static inline void prelude_list_splice(prelude_list_t *head, prelude_list_t *added)
{
        if ( ! prelude_list_is_empty(added) )
                __list_splice(head, added);
}


static void multidimensional_capture_to_multiple_string(prelude_list_t *outlist,
                                                        value_item_reference_t *vitem, capture_string_t *capture)
{
        unsigned int index, i;
        prelude_list_t *tmp, *bkp;
        prelude_string_t *str, *base;
        
        if ( prelude_list_is_empty(outlist) ) {                
                index = capture_string_get_index(capture);
                        
                for ( i = 0; i < index; i++ ) {
                        void *sub = capture_string_get_element(capture, i);
                        assert(capture_string_is_element_string(capture, i));

                        prelude_string_new_dup(&str, sub);
                        prelude_linked_object_add_tail(outlist, (prelude_linked_object_t *) str);
                }
        }
        
        else {
                prelude_list_t newlist;
                prelude_list_init(&newlist);
                                
                index = capture_string_get_index(capture);
                                
                prelude_list_for_each_safe(outlist, tmp, bkp) {
                        base = prelude_linked_object_get_object(tmp);
                        prelude_linked_object_del_init((prelude_linked_object_t *) base);
                        
                        for ( i = 0; i < index; i++ ) {
                                void *sub = capture_string_get_element(capture, i);
                                
                                /*
                                 * As of now, the list should be flat
                                 */
                                assert(capture_string_is_element_string(capture, i));
                                
                                prelude_string_new_dup(&str, prelude_string_get_string(base));
                                prelude_string_cat(str, sub);
                                prelude_linked_object_add_tail(&newlist, (prelude_linked_object_t *) str);
                        }
                        
                        prelude_string_destroy(base);
                }

                prelude_list_splice(outlist, &newlist);
        }
}



static void resolve_referenced_value(prelude_list_t *outlist, value_item_reference_t *vitem,
                                     pcre_plugin_t *plugin, const pcre_rule_t *rule, capture_string_t *capture)
{
        unsigned int index;
         
        index = capture_string_get_index(capture);
        
        if ( (vitem->refno - 1) < 0 || (vitem->refno - 1) >= index ) {
                prelude_log(PRELUDE_LOG_ERR, "Invalid reference: %d (max is %u).\n", vitem->refno, index);
                return;
        }


        if ( ! capture_string_is_element_string(capture, vitem->refno - 1) ) {
                capture_string_t *sub = capture_string_get_element(capture, vitem->refno - 1);
                
                if ( vitem->multiple_value )
                        multidimensional_capture_to_multiple_string(outlist, vitem, sub);
                
                else if ( vitem->list_index )
                        multidimensional_capture_with_index(outlist, vitem, plugin, rule, sub);
                else
                        multidimensional_capture_to_flat_string(outlist, vitem, sub);
        } else
                propagate_string(outlist, capture_string_get_element(capture, vitem->refno - 1));
}



static int get_matching_context(pcre_plugin_t *plugin, prelude_list_t *outlist, prelude_string_t *str)
{
        int ret;
        pcre *regex;
        int error_offset;
        const char *err_ptr;
        
        prelude_string_cat(str, "$");
                
        regex = pcre_compile(prelude_string_get_string(str), 0, &err_ptr, &error_offset, NULL);
        if ( ! regex ) {
                prelude_log(PRELUDE_LOG_ERR, "unable to compile regex: %s.\n", err_ptr);
                return -1;
        }
        
        ret = pcre_context_search_regex(outlist, plugin, regex);
        pcre_free(regex);

        return ret;
}



static int resolve_referenced_context(prelude_list_t *outlist, value_item_context_t *vitem,
                                      pcre_plugin_t *plugin, const pcre_rule_t *rule, capture_string_t *capture)
{
        int i, ret, nth;
        pcre_context_t *ctx;
        prelude_string_t *out;
        prelude_list_t str_list, ctx_list, *tmp, *bkp, *tmp1, *bkp1;

        prelude_list_init(&str_list);
        
        nth = value_container_resolve_listed(&str_list, vitem->context, plugin, rule, capture);
        if ( nth < 0 )
                return -1;

        prelude_list_for_each_safe(&str_list, tmp, bkp) {
                
                out = prelude_linked_object_get_object(tmp);
                i = get_matching_context(plugin, &ctx_list, out);
                prelude_string_destroy(out);

                if ( i < 0 )
                        continue;
                
                prelude_list_for_each_safe(&ctx_list, tmp1, bkp1) {
                        ctx = prelude_linked_object_get_object(tmp1);                        
                        prelude_linked_object_del((prelude_linked_object_t *) ctx);
                        
                        prelude_string_new(&out);
                        
                        ret = pcre_context_get_value_as_string(ctx, out);
                        if ( ret < 0 ) {
                                if ( pcre_context_get_type(ctx) == PCRE_CONTEXT_TYPE_IDMEF ) {
                                        /* Special case, IDMEF is handled directly trhough pcre-context.c */
                                        prelude_string_sprintf(out, "$%s", pcre_context_get_name(ctx));
                                } else {
                                        prelude_perror(ret, "no value");
                                        prelude_string_destroy(out);
                                        continue;
                                }
                        }
                        
                        if ( i > 1 || nth > 1 )
                                prelude_linked_object_add_tail(outlist, (prelude_linked_object_t *) out);
                        else {
                                propagate_string(outlist, prelude_string_get_string(out));
                                prelude_string_destroy(out);
                        }
                }
        }

        return 0;
}



int value_container_resolve_listed(prelude_list_t *outlist, value_container_t *vcont,
                                   pcre_plugin_t *plugin, const pcre_rule_t *rule, capture_string_t *capture)
{
        int nth = 0;
        prelude_list_t *tmp;
        value_item_t *vitem;
        
        prelude_list_for_each(&vcont->value_item_list, tmp) {
                vitem = prelude_list_entry(tmp, value_item_t, list);

                if ( vitem->type == VALUE_ITEM_REFERENCE )
                        resolve_referenced_value(outlist, (value_item_reference_t *) vitem, plugin, rule, capture);

                else if ( vitem->type == VALUE_ITEM_CONTEXT )
                        resolve_referenced_context(outlist, (value_item_context_t *) vitem, plugin, rule, capture);
                
                else if ( vitem->type == VALUE_ITEM_FIXED )
                        propagate_string(outlist, ((value_item_fixed_t *) vitem)->value);
        }

        /*
         * FIXME.
         */
        prelude_list_for_each(outlist, tmp)
                nth++;
                
        return nth;
}



prelude_string_t *value_container_resolve(value_container_t *vcont, pcre_plugin_t *plugin,
                                          const pcre_rule_t *rule, capture_string_t *capture)
{
        int ret;
        prelude_string_t *str = NULL;
        prelude_list_t outlist, *tmp, *bkp;
        
        prelude_list_init(&outlist);
        
        ret = value_container_resolve_listed(&outlist, vcont, plugin, rule, capture);
        if ( ret < 0 )
                return NULL;
        
        prelude_list_for_each_safe(&outlist, tmp, bkp) {
                assert(str == NULL);
                
                str = prelude_linked_object_get_object(tmp);
                prelude_linked_object_del_init((prelude_linked_object_t *) str);
        }
        
        return str;
}




int value_container_new(value_container_t **vcont, const char *str)
{
        int ret;
        
        *vcont = malloc(sizeof(**vcont));
        if ( ! *vcont )
                return prelude_error_from_errno(errno);

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

        if ( ! vcont )
                return;
        
        prelude_list_for_each_safe(&vcont->value_item_list, tmp, bkp) {
                vitem = prelude_list_entry(tmp, value_item_t, list);

                if ( vitem->type == VALUE_ITEM_FIXED )
                        free(((value_item_fixed_t *)vitem)->value);

                else if ( vitem->type == VALUE_ITEM_CONTEXT )
                        value_container_destroy(((value_item_context_t *) vitem)->context);

                else if ( vitem->type == VALUE_ITEM_REFERENCE )
                        value_container_destroy(((value_item_reference_t *) vitem)->list_index);
                
                prelude_list_del(&vitem->list);
                free(vitem);
        }

        free(vcont);
}



void value_container_reset(value_container_t *vcont)
{
#if 0
        value_item_t *vitem;
        prelude_list_t *tmp;
        
        prelude_list_for_each(&vcont->value_item_list, tmp) {
                vitem = prelude_list_entry(tmp, value_item_t, list);

                if ( vitem->type == VALUE_ITEM_FIXED ) {
                        free(((value_item_fixed_t *)vitem)->value);
                        ((value_item_fixed_t *)vitem)->value = NULL;
                }

                else if ( vitem->type == VALUE_ITEM_CONTEXT ) {
                        free(((value_item_context_t *)vitem)->context);
                        ((value_item_context_t *)vitem)->context = NULL;
                }
        }
#endif
}



void *value_container_get_data(value_container_t *vcont)
{
        return vcont->data;
}


void value_container_set_data(value_container_t *vcont, void *data)
{
        vcont->data = data;
}
