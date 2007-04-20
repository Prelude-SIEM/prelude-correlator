/*****
*
* Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006 PreludeIDS Technologies. All Rights Reserved.
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
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <time.h>
#include <pcre.h>
#include <assert.h>
#include <signal.h>

#include <libprelude/prelude-log.h>

#include "prelude-correlator.h"

#include "pcre-mod.h"
#include "pcre-context.h"
#include "rule-object.h"
#include "rule-regex.h"


#include "pcre-parser.h"

int pcre_LTX_prelude_plugin_version(void);
int pcre_LTX_correlation_plugin_init(prelude_plugin_entry_t *pe, void *data);


struct pcre_plugin {
        int rulesnum;
        char *rulesetdir;
        
        prelude_bool_t last_rules_first;
        prelude_bool_t dump_unmatched;
        
        prelude_list_t rule_list;
        prelude_list_t context_list;

        prelude_list_t schedule_list;
        prelude_timer_t schedule_timer;

        unsigned int restored_context_count;
};


struct action_cb {
        value_container_t *target_context;
        rule_object_list_t *object_list;
};


struct context_cb {
        prelude_bool_t addition;
        
        value_container_t *left_value;
        value_container_t *right_value;
        rule_object_list_t *rule_object_list;
};


typedef enum {
        IF_OPERATOR_EQUAL   = 0x01,
        IF_OPERATOR_LOWER   = 0x02,
        IF_OPERATOR_GREATER = 0x04,
} if_operator_type_t;


struct if_cb {
        prelude_list_t list;
        
        value_container_t *if_vcont;
        if_operator_type_t if_op;
        float if_value;
        prelude_list_t if_operation_list;
        
        value_container_t *else_vcont;
        if_operator_type_t else_op;
        float else_value;        
        prelude_list_t else_operation_list;
};


struct for_cb {
        prelude_list_t list;
        prelude_list_t operation_list;

        char *var;
        value_container_t *iteration_vcont;
};


struct schedule_cb {
        prelude_list_t list;
        pcre_rule_t *rule;
        
        int minute_min;
        int minute_max;
        int minute_skip;
        
        int hour_min;
        int hour_max;
        int hour_skip;
        
        int dom_min;
        int dom_max;
        int dom_skip;
        
        int month_min;
        int month_max;
        int month_skip;

        int dow_min;
        int dow_max;
        int dow_skip;
};


static void free_rule_container(pcre_rule_container_t *rc);

static int parse_ruleset(prelude_list_t *head, pcre_plugin_t *plugin, pcre_rule_t *rule,
                         prelude_list_t *operation_list, const char *filename, unsigned int *line, FILE *fd);



static prelude_correlator_plugin_t pcre_plugin;



static int add_operation(prelude_list_t *head, int (*op_cb)(pcre_plugin_t *plugin, pcre_rule_t *rule,
                                                            idmef_message_t *input, capture_string_t *capture, void *extra,
                                                            prelude_list_t *context_result), void (*extra_destroy)(void *extra),
                         void *extra)
{
        pcre_operation_t *op;

        op = calloc(1, sizeof(*op));
        if ( ! op )
                return -1;

        op->op = op_cb;
        op->extra = extra;
        op->extra_destroy = extra_destroy;
        
        prelude_list_add_tail(head, &op->list);
        
        return 0;
}



static pcre_context_t *lookup_context(value_container_t *vcont, pcre_plugin_t *plugin,
                                       pcre_rule_t *rule, capture_string_t *capture)
{
        prelude_string_t *str;
        pcre_context_t *ctx = NULL;
        
        str = value_container_resolve(vcont, plugin, rule, capture);
        if ( ! str )
                return NULL;

        ctx = pcre_context_search(plugin, prelude_string_get_string(str));
        prelude_string_destroy(str);
        
        return ctx;
}


static int foreach_value_context(value_container_t *vcont, pcre_plugin_t *plugin,
                                 pcre_rule_t *rule, capture_string_t *capture, void *extra,
                                 int (*cb)(pcre_plugin_t *plugin, pcre_context_t *ctx, void *extra)) 
{
        int ret;
        pcre_context_t *ctx;
        prelude_string_t *str;
        prelude_list_t list, *tmp, *bkp, ctx_list, *tmp1, *bkp1;
        
        prelude_list_init(&list);
        
        ret = value_container_resolve_listed(&list, vcont, plugin, rule, capture);
        if ( ret < 0 )
                return ret;
        
        prelude_list_for_each_safe(&list, tmp, bkp) {
                str = prelude_linked_object_get_object(tmp);
                
                if ( ret >= 0 ) {
                        prelude_list_init(&ctx_list);
                        pcre_context_search_regex(&ctx_list, plugin, prelude_string_get_string(str));

                        prelude_list_for_each_safe(&ctx_list, tmp1, bkp1) {
                                ctx = prelude_linked_object_get_object(tmp1);
                                ret = cb(plugin, ctx, extra);
                        }
                }
                
                prelude_string_destroy(str);
        }

        return ret;
}




/*
 * Callback operation.
 */

static int op_create_context(pcre_plugin_t *plugin, pcre_rule_t *rule,
                             idmef_message_t *input, capture_string_t *capture, void *extra,
                             prelude_list_t *context_result)
{
        int ret;
        pcre_context_t *ctx;
        prelude_string_t *str;
        prelude_list_t outlist, *tmp, *bkp;
        pcre_context_setting_t *pcs = extra;
        
        prelude_list_init(&outlist);
        
        ret = value_container_resolve_listed(&outlist, pcs->vcont, plugin, rule, capture);
        if ( ret < 0 )
                return -1;

        prelude_list_for_each_safe(&outlist, tmp, bkp) {
                str = prelude_linked_object_get_object(tmp);
                
                ret = pcre_context_new(&ctx, plugin, prelude_string_get_string(str), pcs);                
                prelude_string_destroy(str);
                
                if ( ret < 0 && ret != -2 ) 
                        return -1;
        }

        return 0;
}



static int op_check_req_context(pcre_plugin_t *plugin, pcre_rule_t *rule,
                                idmef_message_t *input, capture_string_t *capture, void *extra,
                                prelude_list_t *context_result)
{
        pcre_context_t *ctx;

        prelude_log_debug(4, "checking required context.\n");
        ctx = lookup_context(extra, plugin, rule, capture);

        return ctx ? 0 : -1;
}


static int not_context_cb(pcre_plugin_t *plugin, pcre_context_t *ctx, void *extra)
{
        return -1;
}


static int op_check_not_context(pcre_plugin_t *plugin, pcre_rule_t *rule,
                                idmef_message_t *input, capture_string_t *capture, void *extra,
                                prelude_list_t *context_result)
{
        prelude_log_debug(4, "checking not context.\n");
        return foreach_value_context(extra, plugin, rule, capture, NULL, not_context_cb);
}



static int destroy_context_cb(pcre_plugin_t *plugin, pcre_context_t *ctx, void *extra)
{
        pcre_context_destroy(ctx);
        return 0;
}



static int op_destroy_context(pcre_plugin_t *plugin, pcre_rule_t *rule,
                              idmef_message_t *input, capture_string_t *capture, void *extra,
                              prelude_list_t *context_result)
{
        foreach_value_context(extra, plugin, rule, capture, NULL, destroy_context_cb);
        return 0;
}


static int op_alert(pcre_plugin_t *plugin, pcre_rule_t *rule,
                    idmef_message_t *input, capture_string_t *capture, void *extra,
                    prelude_list_t *context_result)
{
        int ret;
        prelude_string_t *str;
        pcre_context_t *ctx = NULL;
        prelude_list_t list, *tmp, *bkp;
        
        prelude_list_init(&list);
        
        ret = value_container_resolve_listed(&list, extra, plugin, rule, capture);        
        if ( ret < 0 )
                return -1;
        
        prelude_list_for_each_safe(&list, tmp, bkp) {
                str = prelude_linked_object_get_object(tmp);

                ctx = pcre_context_search(plugin, prelude_string_get_string(str));
                if ( ! ctx )
                        prelude_log(PRELUDE_LOG_ERR, "alert on non existant context '%s'.\n", prelude_string_get_string(str));
                else {
                        if ( ! pcre_context_get_value_idmef(ctx) )
                                prelude_log(PRELUDE_LOG_ERR, "'%s' context contain no idmef value.\n", prelude_string_get_string(str));
                        else {
                                prelude_log_debug(3, "[%s]: emit alert.\n", pcre_context_get_name(ctx));
                                correlation_alert_emit(pcre_context_get_value_idmef(ctx));
                        }
                }
                
                prelude_string_destroy(str);
        
        }
                        
        return 0;
}


static int op_check_correlation(pcre_plugin_t *plugin, pcre_rule_t *rule,
                                idmef_message_t *input, capture_string_t *capture,
                                void *extra, prelude_list_t *context_result)
{
        int ret;
        pcre_context_t *ctx;
        
        ctx = lookup_context(extra, plugin, rule, capture);
        if ( ! ctx ) 
                return -1;
        
        ret = pcre_context_check_correlation(ctx);
        if ( ret < 0 )
                return -1;

        return 0;
}



static int timer_reset_cb(pcre_plugin_t *plugin, pcre_context_t *ctx, void *extra)
{
        pcre_context_reset_timer(ctx);
        return 0;
}


static int op_reset_timer(pcre_plugin_t *plugin, pcre_rule_t *rule,
                          idmef_message_t *input, capture_string_t *capture, void *extra,
                          prelude_list_t *context_result)
{
        return foreach_value_context(extra, plugin, rule, capture, NULL, timer_reset_cb);
}



static int do_op_if(pcre_plugin_t *plugin, pcre_rule_t *rule, prelude_string_t *str,
                    idmef_message_t *input, capture_string_t *capture,
                    int op, float value, prelude_list_t *operation_list)
{
        float val;
        prelude_bool_t ok = FALSE;
        
        if ( prelude_string_is_empty(str) )
                return -1;
        
        if ( op != 0 ) {
                val = (float) strtod(prelude_string_get_string(str), NULL);
        
                if ( op & IF_OPERATOR_EQUAL && val == value )
                        ok = TRUE;

                else if ( op & IF_OPERATOR_LOWER && val < value )
                        ok = TRUE;
                
                else if ( op & IF_OPERATOR_GREATER && val > value )
                        ok = TRUE;
        
                if ( ! ok )
                        return -1;
        }

        pcre_operation_execute(plugin, rule, operation_list, input, capture);
        return 0;
}


static int op_if(pcre_plugin_t *plugin, pcre_rule_t *rule,
                 idmef_message_t *input, capture_string_t *capture, void *extra,
                 prelude_list_t *context_result)
{
        int ret;
        prelude_string_t *str;
        struct if_cb *ifcb = extra;
        prelude_bool_t do_else = TRUE;
        prelude_list_t list, *tmp, *bkp;
        
        prelude_list_init(&list);
        
        if ( ifcb->if_vcont ) {
                ret = value_container_resolve_listed(&list, ifcb->if_vcont, plugin, rule, capture);
                if ( ret < 0 ) 
                        return 0;

                prelude_list_for_each_safe(&list, tmp, bkp) {
                        str = prelude_linked_object_get_object(tmp);
                        
                        ret = do_op_if(plugin, rule, str, input, capture, ifcb->if_op, ifcb->if_value, &ifcb->if_operation_list);
                        
                        prelude_string_destroy(str);
                        if ( ret == 0 )
                                do_else = FALSE;
                }
        }

        else if ( ifcb->if_value ) {
                pcre_operation_execute(plugin, rule, &ifcb->if_operation_list, input, capture);
                do_else = FALSE;
        }

        if ( ! do_else )
                return 0;
        
        if ( ifcb->else_vcont ) {
                
                ret = value_container_resolve_listed(&list, ifcb->else_vcont, plugin, rule, capture);
                if ( ret < 0 )
                        return 0;

                prelude_list_for_each_safe(&list, tmp, bkp) {
                        str = prelude_linked_object_get_object(tmp);
                        
                        do_op_if(plugin, rule, str, input, capture, ifcb->else_op, ifcb->else_value, &ifcb->else_operation_list);
                        prelude_string_destroy(str);
                }
        }
        
        else if ( ! prelude_list_is_empty(&ifcb->else_operation_list) )
                do_op_if(plugin, rule, NULL, input, capture, ifcb->else_op, ifcb->else_value, &ifcb->else_operation_list);
        
        return 0;
}


static int op_for(pcre_plugin_t *plugin, pcre_rule_t *rule,
                  idmef_message_t *input, capture_string_t *capture, void *extra,
                  prelude_list_t *context_result)
{
        int ret;
        prelude_string_t *str;
        pcre_context_t *ctx = NULL;
        prelude_list_t list, *tmp, *bkp;
        struct for_cb *forcb = extra;
        
        prelude_list_init(&list);
        
        ret = value_container_resolve_listed(&list, forcb->iteration_vcont, plugin, rule, capture);
        if ( ret < 0 )
                return ret;

        ret = pcre_context_new(&ctx, plugin, forcb->var, NULL);
        if ( ret < 0 )
                return ret;
        
        prelude_list_for_each_safe(&list, tmp, bkp) {
                str = prelude_linked_object_get_object(tmp);
                assert(! prelude_string_is_empty(str));                

                pcre_context_set_value_from_string(plugin, ctx, prelude_string_get_string(str));
                prelude_string_destroy(str);

                pcre_operation_execute(plugin, rule, &forcb->operation_list, input, capture);
        }

        pcre_context_destroy(ctx);
        
        return 0;
}




/*
 * Key parsing operation.
 */
static int parse_key_and_value(char *input, char **key, char **value) 
{
        char *ptr, *tmp;
        
        *value = NULL;
        
        /*
         * filter space at the begining of the line.
         */
        while ( isspace(*input) )
                input++;
        
        if ( *input == '\0' )
                return -1;
        
        *key = input;
        
        /*
         * search first '=' in the input,
         * corresponding to the key = value separator.
         */
        tmp = ptr = input + strcspn(input, "=:;");

        if ( ! *ptr ) /* key without value */
                return 0;
        
        /*
         * strip whitespace at the tail of the key.
         */
        while ( tmp && (*tmp == '=' || *tmp == ':' || *tmp == ';' || isspace((int) *tmp)) )
                *tmp-- = '\0';

        /*
         * strip whitespace at the begining of the value.
         */
        ptr++;
        while ( isspace((int) *ptr) )
                ptr++;

        *value = ptr;

        /*
         * strip whitespace at the end of the value.
         */
        ptr = ptr + strlen(ptr) - 1;
        while ( isspace((int) *ptr) )
                *ptr-- = '\0';

        if ( *ptr == ';' )
                *ptr = 0;
        
        return 0;
}


static int parse_multiple_key_and_value(const char **input, char **key, char **value)
{
        int ret;
        char *ptr;
        union { char **rw; const char **ro; } val;

        val.ro = input;
        
        ptr = strsep(val.rw, ";");
        if ( ! ptr )
                return 0;

        ret = parse_key_and_value(ptr, key, value);
        if ( ret < 0 )
                return ret;

        return 1;
}


static pcre_rule_container_t *create_rule_container(pcre_rule_t *rule)
{
        pcre_rule_container_t *rc;

        rc = calloc(1, sizeof(*rc));
        if ( ! rc ) {
                prelude_log(PRELUDE_LOG_ERR, "memory exhausted.\n");
                return NULL;
        }
        
        rc->rule = rule;
        rule->refcount++;
        
        return rc;
}



static int parse_rule_id(pcre_plugin_t *plugin, pcre_rule_t *rule,
                         prelude_list_t *operation_list, const char *variable, const char *value) 
{
        rule->id = (unsigned int) strtoul(value, NULL, 0);
        return 0;
}



static int parse_rule_revision(pcre_plugin_t *plugin, pcre_rule_t *rule,
                               prelude_list_t *operation_list, const char *variable, const char *value) 
{
        rule->revision = (unsigned int) strtoul(value, NULL, 0);
        return 0;
}


static pcre_rule_container_t *search_rule(prelude_list_t *head, int id)
{
        prelude_list_t *tmp;
        pcre_rule_container_t *cur;
        
        prelude_list_for_each(head, tmp) {
                cur = prelude_list_entry(tmp, pcre_rule_container_t, list);
                
                if ( cur->rule->id == id )
                        return cur;
                
                cur = search_rule(&cur->rule->rule_list, id);
                if ( cur )
                        return cur;
        }

        return NULL;
}


static int parse_rule_last(pcre_plugin_t *plugin, pcre_rule_t *rule,
                           prelude_list_t *operation_list, const char *variable, const char *value)
{
        rule->flags |= PCRE_RULE_FLAGS_LAST;
        return 0;
}


static int parse_rule_silent(pcre_plugin_t *plugin, pcre_rule_t *rule,
                             prelude_list_t *operation_list, const char *variable, const char *value)
{        
        rule->flags |= PCRE_RULE_FLAGS_SILENT;
        return 0;
}


static int parse_require_context(pcre_plugin_t *plugin, pcre_rule_t *rule,
                                 prelude_list_t *operation_list, const char *variable, const char *value)
{
        int ret;
        value_container_t *vcont;

        if ( *value != '$' )
                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "context miss prefix: '%s'", value);
        
        ret = value_container_new(&vcont, value + 1);
        if ( ret < 0 )
                return ret;

        return add_operation(operation_list, op_check_req_context, (void *) value_container_destroy, vcont);
}


static int parse_check_correlation(pcre_plugin_t *plugin, pcre_rule_t *rule,
                                   prelude_list_t *operation_list, const char *variable, const char *value)
{
        int ret;
        value_container_t *vcont;

        if ( *value != '$' )
                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "context miss prefix: '%s'", value);
        
        ret = value_container_new(&vcont, value + 1);
        if ( ret < 0 )
                return ret;

        return add_operation(operation_list, op_check_correlation, (void *) value_container_destroy, vcont);
}



static int parse_reset_timer(pcre_plugin_t *plugin, pcre_rule_t *rule,
                             prelude_list_t *operation_list, const char *variable, const char *value)
{
        int ret;
        value_container_t *vcont;

        if ( *value != '$' )
                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "context miss prefix: '%s'", value);
        
        ret = value_container_new(&vcont, value + 1);
        if ( ret < 0 )
                return ret;

        return add_operation(operation_list, op_reset_timer, (void *) value_container_destroy, vcont);
}


static int parse_not_context(pcre_plugin_t *plugin, pcre_rule_t *rule,
                             prelude_list_t *operation_list, const char *variable, const char *value)
{
        int ret;
        value_container_t *vcont;

        if ( *value != '$' )
                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "context miss prefix: '%s'", value);
        
        ret = value_container_new(&vcont, value + 1);
        if ( ret < 0 )
                return ret;

        return add_operation(operation_list, op_check_not_context, (void *) value_container_destroy, vcont);
}




static int parse_destroy_context(pcre_plugin_t *plugin, pcre_rule_t *rule,
                                 prelude_list_t *operation_list, const char *variable, const char *value)
{
        int ret;
        value_container_t *vcont;

        if ( *value != '$' )
                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "context miss prefix: '%s'", value);
        
        ret = value_container_new(&vcont, value + 1);
        if ( ret < 0 )
                return ret;

        return add_operation(operation_list, op_destroy_context, (void *) value_container_destroy, vcont);
}



static int _parse_create_context(prelude_list_t *operation_list, const char *arg, pcre_context_setting_flags_t flags)
{
        int ret;
        char *key, *value;
        const char *cname = NULL;
        pcre_context_setting_t *pcs;
        
        pcs = calloc(1, sizeof(*pcs));
        if ( ! pcs )
                return -1;

        pcs->timeout = 60;
        pcs->flags = flags;

        while ( (ret = parse_multiple_key_and_value(&arg, &key, &value)) == 1 ) {                
                
                if ( ! cname )
                        cname = key;
                
                else if ( strcmp(key, "alert_on_destroy") == 0 )
                        pcs->flags |= PCRE_CONTEXT_SETTING_FLAGS_ALERT_ON_DESTROY;
                
                else if ( strcmp(key, "alert_on_expire") == 0 )
                        pcs->flags |= PCRE_CONTEXT_SETTING_FLAGS_ALERT_ON_EXPIRE;
                
                else if ( strcmp(key, "threshold") == 0 )
                        pcs->correlation_threshold = atoi(value);
                
                else if ( strcmp(key, "expire") == 0 )
                        pcs->timeout = atoi(value);

                else if ( strcmp(key, "unique") == 0 ) {
                        ret = idmef_path_new_fast(&pcs->unique_path, value);
                        if ( ret < 0 ) {
                                prelude_log(PRELUDE_LOG_WARN, "Could not create unique path '%s': %s.\n", value, prelude_strerror(ret));
                                pcre_context_setting_destroy(pcs);
                                return ret;
                        }
                        
                        printf("unique = %p\n", pcs->unique_path);
                } else {
                        pcre_context_setting_destroy(pcs);
                        prelude_log(PRELUDE_LOG_WARN, "Unknown context creation argument: '%s'.\n", key);
                        return -1;
                }
        }
        
        if ( ret == 0 ) {
                value_container_new(&pcs->vcont, cname);
                ret = add_operation(operation_list, op_create_context, (void *) pcre_context_setting_destroy, pcs);
        }
        
        if ( ret < 0 )
                pcre_context_setting_destroy(pcs);
        
        return ret;
}


static int parse_create_context(pcre_plugin_t *plugin, pcre_rule_t *rule,
                                prelude_list_t *operation_list, const char *variable, const char *value)
{
        return _parse_create_context(operation_list, value, 0);
}


static int parse_set_context(pcre_plugin_t *plugin, pcre_rule_t *rule,
                             prelude_list_t *operation_list, const char *variable, const char *value)
{
        return _parse_create_context(operation_list, value, PCRE_CONTEXT_SETTING_FLAGS_OVERWRITE);
}


static int parse_add_context(pcre_plugin_t *plugin, pcre_rule_t *rule,
                             prelude_list_t *operation_list, const char *variable, const char *value)
{
        return _parse_create_context(operation_list, value, PCRE_CONTEXT_SETTING_FLAGS_QUEUE);
}


static pcre_operation_t *get_last_operation(prelude_list_t *operation_list)
{
        prelude_list_t *tmp;
        pcre_operation_t *op;
        
        prelude_list_for_each_reversed(operation_list, tmp) {
                op = prelude_list_entry(tmp, pcre_operation_t, list);
                return op;
        }

        return NULL;
}


static int parse_pattern(pcre_plugin_t *plugin, pcre_rule_t *rule,
                         prelude_list_t *operation_list, const char *variable, const char *pattern)
{
        int ret;
        rule_regex_t *new;
        char *value, *key;
               
        do {
                ret = parse_multiple_key_and_value(&pattern, &key, &value);                
                if ( ret != 1 )
                        return ret;
                
                ret = rule_regex_new(&new, key, value);
                if ( ret < 0 )
                        return ret;
                
                prelude_linked_object_add_tail(&rule->regex_list, (prelude_linked_object_t *) new);
        } while ( 1 );

        return 0;
}


static int parse_schedule_entry(const char *entry, int *min, int *max, int *skip)
{
        char *eptr;

        *skip = 0;
        
        *min = *max = strtol(entry, &eptr, 10);
        if ( eptr == entry ) {
                if ( *entry == '*' ) {
                        entry++;
                        *min = *max = -1;
                } else
                        return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "expected a number got '%s'", entry);
        }

        else {
                entry = eptr;
                if ( *entry == '-' ) {
                        entry++;
                        
                        *max = strtol(entry, &eptr, 10);
                        if ( entry == eptr )
                                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "invalid range specified");

                        entry = eptr;
                }
        }

        if ( *entry == '/' ) {
                entry++;
                
                *skip = strtol(entry, &eptr, 10);
                if ( eptr == entry )
                        return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "invalid skip value: '%s'", entry);
        }
        
        return 0;
}



static int match_schedule_entry(int cur, int min, int max, int skip)
{
        if ( min == -1 && max == -1 )
                return 0;
        
        if ( cur < min || cur > max )
                return -1;

        return 0;
}


static int match_schedule(struct schedule_cb *scb, struct tm *t)
{        
        if ( match_schedule_entry(t->tm_min, scb->minute_min, scb->minute_max, scb->minute_skip) < 0 )
                return -1;

        if ( match_schedule_entry(t->tm_hour, scb->hour_min, scb->hour_max, scb->hour_skip) < 0 )
                return -1;

        if ( match_schedule_entry(t->tm_mday, scb->dom_min, scb->dom_max, scb->dom_skip) < 0 )
                return -1;

        if ( match_schedule_entry(t->tm_mon, scb->month_min, scb->month_max, scb->month_skip) < 0 )
                return -1;

        if ( match_schedule_entry(t->tm_wday, scb->dow_min, scb->dow_max, scb->dow_skip) < 0 )
                return -1;

        return 0;
}


static void op_schedule(void *data)
{
        int ret;
        time_t t;
        struct tm *tval;
        prelude_list_t *tmp;
        pcre_plugin_t *plugin = data;
        struct schedule_cb *scb;

        t = time(NULL);
        tval = localtime(&t);
        
        prelude_list_for_each(&plugin->schedule_list, tmp) {
                scb = prelude_list_entry(tmp, struct schedule_cb, list);

                ret = match_schedule(scb, tval);
                if ( ret == 0 )
                        pcre_operation_execute(plugin, scb->rule, &scb->rule->operation_list, NULL, NULL);
        }

        prelude_timer_reset(&plugin->schedule_timer);
}



static int check_schedule(int min, int max, int input_min, int input_max)
{
        if ( input_min != -1 && (input_min < min || input_min > max) )
                return -1;
        
        if ( input_max != -1 && (input_max < min || input_max > max) )
                return -1;

        return 0;
}


static int parse_schedule(pcre_plugin_t *plugin, pcre_rule_t *rule,
                          prelude_list_t *operation_list, const char *variable, const char *value)
{
        int ret, i;
        char *ptr = NULL;
        struct schedule_cb *scb;
 
        scb = malloc(sizeof(*scb));
        if ( ! scb )
                return prelude_error_from_errno(errno);
        
        scb->rule = rule;
        
        for ( i = 0; i < 5; i++ ) {
                ptr = strtok(value, " ");
                if ( ! ptr )
                        break;

                value = NULL;
                                
                if ( i == 0 ) {
                        ret = parse_schedule_entry(ptr, &scb->minute_min, &scb->minute_max, &scb->minute_skip);
                        if ( ret < 0 )
                                return ret;
                        
                        if ( check_schedule(0, 59, scb->minute_min, scb->minute_max) < 0 )
                                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "minute should fit in 0-59 range");
                }
                
                else if ( i == 1 ) {
                        ret = parse_schedule_entry(ptr, &scb->hour_min, &scb->hour_max, &scb->hour_skip);
                        if ( ret < 0 )
                                return ret;
                        
                        if ( check_schedule(0, 23, scb->hour_min, scb->hour_max) < 0 )
                                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "hour should fit in 0-23 range");
                }
                
                else if ( i == 2 ) {
                        ret = parse_schedule_entry(ptr, &scb->dom_min, &scb->dom_max, &scb->dom_skip);
                        if ( ret < 0 )
                                return ret;
                        
                        if ( check_schedule(1, 31, scb->dom_min, scb->dom_max) < 0 )
                                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "day of month should fit in 1-31 range");
                }
                
                else if ( i == 3 ) {
                        ret = parse_schedule_entry(ptr, &scb->month_min, &scb->month_max, &scb->month_skip);
                        if ( ret < 0 )
                                return ret;

                        if ( check_schedule(0, 12, scb->month_min, scb->month_max) < 0 )
                                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "month should fit in 0-12 range");
                }
                
                else if ( i == 4 ) {
                        ret = parse_schedule_entry(ptr, &scb->dow_min, &scb->dow_max, &scb->dow_skip);
                        if ( ret < 0 )
                                return ret;

                        if ( check_schedule(0, 7, scb->dow_min, scb->dow_max) < 0 )
                                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "day of week should fit in 0-12 range");
                }
        }

        if ( ! ptr )
                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "entry is not complete");

        if ( strtok(NULL, " ") )
                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "entry with too much value");
        
        if ( prelude_list_is_empty(&plugin->schedule_list) ) {
                prelude_timer_set_expire(&plugin->schedule_timer, 60);
                prelude_timer_set_callback(&plugin->schedule_timer, op_schedule);
                prelude_timer_set_data(&plugin->schedule_timer, plugin);
                prelude_timer_init(&plugin->schedule_timer);
        }

        plugin->rulesnum++;
        prelude_list_add_tail(&plugin->schedule_list, &scb->list);
        
        return 0;
}


static int check_func(char **input, const char *fname, char **value)
{
        int ret;
        char *end;
        prelude_string_t *str;
        size_t size = strlen(fname);
        
        ret = strncmp(*input, fname, size);
        if ( ret != 0 )
                return -1;

        *input += size;

        if ( **input != '(' )
                return -1;
        (*input)++;
        
        while ( isspace(**input) ) (*input)++;

        end = strchr(*input, ')');
        if ( ! end )
                return -1;

        ret = prelude_string_new(&str);
        if ( ret < 0 )
                return ret;

        prelude_string_ncat(str, *input, end - *input);
        *input += (end - *input) + 1;

        prelude_string_get_string_released(str, value);
        prelude_string_destroy(str);

        return 0;
}



static int do_exec(prelude_string_t *out, const char *cmd)
{
        FILE *fd;
        size_t len;
        char buf[8192];
        
        fd = popen(cmd, "r");
        if ( ! fd ) {
                prelude_log(PRELUDE_LOG_ERR, "could not open pipe for reading: %s.\n", strerror(errno));
                return -1;
        }

        while ( (len = fread(buf, 1, sizeof(buf), fd)) > 0 )
                prelude_string_ncat(out, buf, len);
        
        if ( pclose(fd) < 0 )
                prelude_log(PRELUDE_LOG_ERR, "error closing pipe: %s.\n", strerror(errno));
        
        return 0;
}



static int context_assign_preprocess(pcre_plugin_t *plugin, pcre_context_t *ctx, prelude_string_t *pstr)
{
        int ret;
        char *str, *val, *tmp;
        
        ret = prelude_string_get_string_released(pstr, &str);
        if ( ret < 0 )
                return ret;

        tmp = str;
        while ( *str ) {
                ret = check_func(&str, "exec", &val);
                if ( ret == 0 ) {
                        do_exec(pstr, val);
                        free(val);
                        continue;
                }
                
                prelude_string_ncat(pstr, str++, 1);
        }
        
        free(tmp);

        if ( ! prelude_string_is_empty(pstr) )
                return pcre_context_set_value_from_string(plugin, ctx, prelude_string_get_string(pstr));

        return 0;
}



static int op_context_assign(pcre_plugin_t *plugin, pcre_rule_t *rule, idmef_message_t *input,
                             capture_string_t *capture, void *extra, prelude_list_t *context_result)
{
        int ret;
        pcre_context_t *ctx;
        prelude_string_t *str;
        idmef_message_t *idmef;
        prelude_list_t list, list2, *tmp, *tmp2, *bkp, *bkp2;
        struct context_cb *cdata = extra;
        
        prelude_list_init(&list);
        
        ret = value_container_resolve_listed(&list, cdata->left_value, plugin, rule, capture);        
        if ( ret < 0 )
                return -1;

        prelude_list_for_each_safe(&list, tmp, bkp) {
                str = prelude_linked_object_get_object(tmp);
                                
                ctx = pcre_context_search(plugin, prelude_string_get_string(str));
                if ( ! ctx )
                        ret = pcre_context_new(&ctx, plugin, prelude_string_get_string(str), NULL);
                
                prelude_string_destroy(str);
                                
                idmef = NULL;
                if ( cdata->right_value ) {  
                        prelude_list_init(&list2);
                                              
                        ret = value_container_resolve_listed(&list2, cdata->right_value, plugin, rule, capture);
                        if ( ret < 0 )
                                return ret;

                        prelude_list_for_each_safe(&list2, tmp2, bkp2) {
                                str = prelude_linked_object_get_object(tmp2);
                                
                                context_assign_preprocess(plugin, ctx, str);
                                prelude_string_destroy(str);
                        }

                        /*
                         * if there was assignement, keep the old IDMEF value to merge with optional obj list
                         */
                        if ( pcre_context_get_type(ctx) == PCRE_CONTEXT_TYPE_IDMEF && ret ) 
                                idmef = pcre_context_get_value_idmef(ctx);
                }
                
                if ( cdata->rule_object_list ) {
                        if ( cdata->addition && pcre_context_get_type(ctx) == PCRE_CONTEXT_TYPE_IDMEF )
                                idmef = pcre_context_get_value_idmef(ctx);
                                                
                        ret = pcre_context_check_unique_count(ctx, input);
                        if ( ret < 0 || ret > 0 )
                                continue;
                                
                        prelude_log_debug(3, "[%s]: running IDMEF assignement list (%s).\n",
                                          pcre_context_get_name(ctx), idmef ? "addition current" : "overwrite current");

                        ret = rule_object_build_message(plugin, rule, cdata->rule_object_list, &idmef, input, capture);
                        if ( ret == 0 )
                                pcre_context_set_value_idmef(ctx, idmef);
                }                
        }
        
        return 0;
}


static void context_assign_destroy(void *data)
{
        struct context_cb *cdata = data;
        
        value_container_destroy(cdata->left_value);

        if ( cdata->right_value )
                value_container_destroy(cdata->right_value);

        if ( cdata->rule_object_list )
                rule_object_list_destroy(cdata->rule_object_list);

        free(cdata);
}



static int idmef_parse(struct context_cb *cdata, const char *arg, char **rem)
{
        int ret;
        char *key, *value, *ptr, *ptr2;
        prelude_string_t *remain;

        prelude_string_new(&remain);

        if ( *arg == '+' && *(arg + 1) == '=' ) {
                cdata->addition = TRUE;
                arg += 2;
                while ( isspace(*arg) ) arg++;
        }
        
        do {                
                ret = parse_multiple_key_and_value(&arg, &key, &value);
                if ( ret != 1 )
                        break;
                
                ptr2 = ptr = strrchr(key, '+');
                if ( ptr ) {
                        while ( ptr2 != key && isspace(*(ptr2 - 1)) )
                                ptr2--;
                        
                        prelude_string_ncat(remain, key, ptr2 - key);

                        ptr++;
                        while ( isspace(*ptr) )
                                ptr++;
                        
                        key = ptr;
                }

                
                ret = rule_object_add(cdata->rule_object_list, key, value); 
                if ( ret < 0 )
                        break;
        } while ( 1 );

        if ( ret >= 0 )
                prelude_string_get_string_released(remain, rem);

        prelude_string_destroy(remain);
        return ret;
}


static int parse_context_assign(pcre_plugin_t *plugin, pcre_rule_t *rule,
                                prelude_list_t *operation_list, const char *target, const char *arg)
{
        int ret;
        char *remain = NULL;
        struct context_cb *cdata;
        
        if ( *target != '$' )
                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "context miss prefix: '%s'", target);

        cdata = calloc(1, sizeof(*cdata));
        if ( ! cdata )
                return prelude_error_from_errno(errno);
        
        ret = value_container_new(&cdata->left_value, target + 1);        
        if ( ret < 0 ) {
                free(cdata);
                return ret;
        }
        
        if ( strchr(arg, '=') ) {
                cdata->rule_object_list = rule_object_list_new();
                if ( ! cdata->rule_object_list ) {
                        context_assign_destroy(cdata);
                        return prelude_error_from_errno(errno);
                }

                ret = idmef_parse(cdata, arg, &remain);
                if ( ret < 0 ) {
                        context_assign_destroy(cdata);
                        return ret;
                }
                
                arg = remain;
        }

        if ( arg ) {                
                ret = value_container_new(&cdata->right_value, arg);
                if ( remain )
                        free(remain);
        
                if ( ret < 0 ) {
                        context_assign_destroy(cdata);
                        return ret;
                }
        }
        
        ret = add_operation(operation_list, op_context_assign, (void *) context_assign_destroy, cdata);
        if ( ret < 0 ) {
                context_assign_destroy(cdata);
                return ret;
        }
        
        return 0;
}



static int parse_alert(pcre_plugin_t *plugin, pcre_rule_t *rule, prelude_list_t *operation_list, const char *variable, const char *value)
{
        int ret;
        value_container_t *vcont;

        if ( *value != '$' )
                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "context miss prefix: '%s'", value);
        
        ret = value_container_new(&vcont, value + 1);        
        if ( ret < 0 )
                return ret;

        ret = add_operation(operation_list, op_alert, (void *) value_container_destroy, vcont);
        if ( ret < 0 ) {
                value_container_destroy(vcont);
                return -1;
        }

        return 0;
}


static int parse_include(pcre_rule_t *rule, pcre_plugin_t *plugin, const char *value) 
{
        int ret;
        FILE *fd;
        char filename[256];
        unsigned int line = 0;
        
        if ( plugin->rulesetdir && value[0] != '/' )
                snprintf(filename, sizeof(filename), "%s/%s", plugin->rulesetdir, value);
        else
                snprintf(filename, sizeof(filename), "%s", value);

        fd = fopen(filename, "r");
        if ( ! fd ) {
                prelude_log(PRELUDE_LOG_ERR, "couldn't open %s for reading: %s.\n", filename, strerror(errno));
                return -1;
        }
        
        ret = parse_ruleset(rule ? &rule->rule_list : &plugin->rule_list, plugin, NULL, NULL, filename, &line, fd);
        fclose(fd);

        return ret;
}


static int parse_global(pcre_plugin_t *plugin, pcre_rule_t *rule,
                        prelude_list_t *operation_list, const char *variable, const char *value) 
{
        int ret;
        pcre_context_t *ctx;

        if ( ! variable )
                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "no variable name provided");
        
        ret = pcre_context_new(&ctx, plugin, variable, NULL); 
        if ( ret == -2 ) /* already exist: restored */
                return 0;

        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "error creating context '%s': %d.\n", variable, ret);
                return ret;
        }
        
        return pcre_context_set_value_from_string(plugin, ctx, value);
}



static void free_operation(prelude_list_t *head)
{
        pcre_operation_t *op;
        prelude_list_t *tmp, *bkp;
        
        prelude_list_for_each_safe(head, tmp, bkp) {
                op = prelude_linked_object_get_object(tmp);

                op->extra_destroy(op->extra);
                free(op);
        }
}


static void if_cb_destroy(struct if_cb *ifcb)
{
        free_operation(&ifcb->if_operation_list);
        free_operation(&ifcb->else_operation_list);

        value_container_destroy(ifcb->if_vcont);

        if ( ifcb->else_vcont )
                value_container_destroy(ifcb->else_vcont);
        
        free(ifcb);
}



static int do_parse_if(FILE *fd, const char *filename, unsigned int *line,
                       pcre_plugin_t *plugin, pcre_rule_t *rule, const char *variable, const char *value,
                       prelude_list_t *operation_list, value_container_t **vcont, if_operator_type_t *if_op, float *if_value)
{
        int ret, i;
        char *eptr;
        size_t len;
        struct {
                const char *operator;
                if_operator_type_t type;
        } optbl[] = {
                { "==", IF_OPERATOR_EQUAL                     },
                { "<=", IF_OPERATOR_LOWER|IF_OPERATOR_EQUAL   },
                { ">=", IF_OPERATOR_GREATER|IF_OPERATOR_EQUAL },
                { "<", IF_OPERATOR_LOWER                      },
                { ">", IF_OPERATOR_GREATER                    }
        };
     
        if ( variable ) {
                ret = value_container_new(vcont, variable);
                if ( ret < 0 )
                        return -1;
        
                for ( i = 0; i < sizeof(optbl) / sizeof(*optbl); i++ ) {
                        len = strlen(optbl[i].operator);
                        
                        if ( strncmp(value, optbl[i].operator, len) == 0 ) {
                                *if_op = optbl[i].type;
                                value += len;
                                break;
                        }
                }
        
                if ( i == sizeof(optbl) / sizeof(*optbl) && *value != '{' )
                        return prelude_error_verbose(PRELUDE_ERROR_GENERIC,
                                                     "Invalid operator specified for 'if' command: '%s'", value);
        }

        /*
         * If there is no value, we just check whether the specified context exist.
         */        
        if ( *value != '{' ) {
                value += strspn(value, " ");
                
                *if_value = strtod(value, &eptr);
                
                if ( eptr == value || (*eptr != ' ' && *eptr != '{') )
                        return prelude_error_verbose(PRELUDE_ERROR_GENERIC,
                                                     "Invalid value specified to 'if' command: '%s'", value);
        }
        
        ret = parse_ruleset(&rule->rule_list, plugin, rule, operation_list, filename, line, fd);        
        if ( ret < 0 )
                return ret;
        
        return 0;
}


static int parse_if(FILE *fd, const char *filename, unsigned int *line,
                    pcre_plugin_t *plugin, pcre_rule_t *rule,
                    prelude_list_t *operation_list, const char *variable, const char *value)
{
        int ret;
        struct if_cb *ifcb;
                
        ifcb = calloc(1, sizeof(*ifcb));
        if ( ! ifcb ) {
                prelude_log(PRELUDE_LOG_ERR, "memory exhausted.\n");
                return -1;
        }
        
        prelude_list_init(&ifcb->if_operation_list);
        prelude_list_init(&ifcb->else_operation_list);

        ret = do_parse_if(fd, filename, line, plugin, rule, variable, value,
                          &ifcb->if_operation_list, &ifcb->if_vcont, &ifcb->if_op, &ifcb->if_value);
        if ( ret < 0 ) {
                if_cb_destroy(ifcb);
                return ret;
        }
                
        ret = add_operation(operation_list, op_if, (void *) if_cb_destroy, ifcb);
        if ( ret < 0 ) {
                if_cb_destroy(ifcb);
                return ret;
        }
        
        return 0;
}


static int parse_else(FILE *fd, const char *filename, unsigned int *line,
                      pcre_plugin_t *plugin, pcre_rule_t *rule,
                      prelude_list_t *operation_list, const char *variable, const char *value)
{
        int ret;
        struct if_cb *ifcb;
        pcre_operation_t *op;
        
        op = get_last_operation(operation_list);
        if ( ! op || op->op != op_if )
                return -1;
        
        ifcb = op->extra;

        ret = do_parse_if(fd, filename, line, plugin, rule, variable, value,
                          &ifcb->else_operation_list, &ifcb->else_vcont, &ifcb->else_op, &ifcb->else_value);
        if ( ret < 0 ) {
                if_cb_destroy(ifcb);
                return ret;
        }
                
        return 0;
}


static void for_cb_destroy(struct for_cb *forcb)
{
        free_operation(&forcb->operation_list);
        value_container_destroy(forcb->iteration_vcont);
        
        free(forcb->var);
        free(forcb);
}


static int parse_for(FILE *fd, const char *filename, unsigned int *line,
                    pcre_plugin_t *plugin, pcre_rule_t *rule,
                    prelude_list_t *operation_list, const char *variable, const char *value)
{
        int ret;
        char *ptr, *eptr;
        struct for_cb *forcb;
                
        forcb = malloc(sizeof(*forcb));
        if ( ! forcb )
                return prelude_error_from_errno(errno);

        prelude_list_init(&forcb->operation_list);

        forcb->var = strdup(variable + 1);
        if ( ! forcb->var ) {
                free(forcb);
                return prelude_error_from_errno(errno);
        }

        ptr = strstr(value, "in ");
        if ( ! ptr )
                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "invalid format for 'for' operation");
        ptr += 3;
        
        eptr = strchr(ptr, ' ');
        if ( eptr )
                *eptr = 0;
        
        ret = value_container_new(&forcb->iteration_vcont, ptr);
        *eptr = ' ';
        
        if ( ret < 0 )
                return ret;
        
        ret = parse_ruleset(&rule->rule_list, plugin, rule, &forcb->operation_list, filename, line, fd);        
        if ( ret < 0 ) {
                for_cb_destroy(forcb);
                return ret;
        }
        
        ret = add_operation(operation_list, op_for, (void *) for_cb_destroy, forcb);
        if ( ret < 0 ) {
                for_cb_destroy(forcb);
                return ret;
        }
        
        return 0;
}



static int parse_rule_included(pcre_plugin_t *plugin, pcre_rule_t *rule,
                               prelude_list_t *operation_list, const char *variable, const char *value)
{
        int ret;
        prelude_list_t *t;
        pcre_rule_container_t tmp, *cur;
        
        tmp.rule = rule;
        prelude_list_add(&plugin->rule_list, &tmp.list);
        
        ret = parse_include(rule, plugin, value);
        
        prelude_list_del(&tmp.list);

        if ( rule ) {
                prelude_list_for_each(&rule->rule_list, t) {
                        cur = prelude_list_entry(t, pcre_rule_container_t, list);
                        cur->optional = 1;
                }
        }
        
        return ret;
}



static int parse_rule_operation(FILE *fd, const char *filename, unsigned int *line,
                                pcre_plugin_t *plugin, pcre_rule_t *rule,
                                prelude_list_t *operation_list,
                                const char *operation, const char *variable, const char *value)
{
        int i, ret;
        struct {
                const char *operation;
                prelude_bool_t need_rule;
                int (*func)(pcre_plugin_t *plugin, pcre_rule_t *rule,
                            prelude_list_t *operation_list, const char *variable, const char *value);
        } keywords[] = {
                { "id"                  , TRUE, parse_rule_id                 },
                { "last"                , TRUE, parse_rule_last               },
                { "revision"            , TRUE, parse_rule_revision           },
                { "silent"              , TRUE, parse_rule_silent             },
                { "include"             , FALSE, parse_rule_included          },
                { "new_context"         , TRUE, parse_create_context          },
                { "set_context"         , TRUE, parse_set_context             },
                { "add_context"         , TRUE, parse_add_context             },
                { "not_context"         , TRUE, parse_not_context             },
                { "destroy_context"     , TRUE, parse_destroy_context         },
                { "require_context"     , TRUE, parse_require_context         },
                { "check_correlation"   , TRUE, parse_check_correlation       },
                { "reset_timer"         , TRUE, parse_reset_timer             },
                { "pattern"             , TRUE, parse_pattern                 },
                { "alert"               , TRUE, parse_alert                   },
                { "global"              , FALSE, parse_global                 },
                { "schedule"            , FALSE, parse_schedule               },
        };

        if ( ! operation ) {
                if ( ! rule )
                        return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "rule should start with the 'pattern' keyword");
                 
                ret = parse_context_assign(plugin, rule, operation_list, variable, value);                        
                if ( ret < 0 )
                        ret = prelude_error_verbose(PRELUDE_ERROR_GENERIC, "context assignement error: %s", prelude_strerror(ret));
                
                return ret;
        }
        
        for ( i = 0; i < sizeof(keywords) / sizeof(*keywords); i++ ) {
                
                if ( strcmp(operation, keywords[i].operation) != 0 )
                        continue;

                if ( keywords[i].need_rule && ! rule )
                        return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "rule should start with the 'pattern' keyword");
                        
                ret = keywords[i].func(plugin, rule, operation_list, variable, value);
                if ( ret < 0 )
                        return ret;
                
                return 1;
        }
        
        if ( strcmp(operation, "if") == 0 )
                return parse_if(fd, filename, line, plugin, rule, operation_list, variable, value);
        
        if ( strncmp(operation, "else", 4) == 0 )
                return parse_else(fd, filename, line, plugin, rule, operation_list, variable, value);

        if ( strcmp(operation, "for") == 0 )
                return parse_for(fd, filename, line, plugin, rule, operation_list, variable, value);
        
        return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "invalid operation: '%s'", operation);
}




static pcre_rule_t *create_rule(void)
{
        pcre_rule_t *rule;

        rule = calloc(1, sizeof(*rule));
        if ( ! rule ) {
                prelude_log(PRELUDE_LOG_ERR, "memory exhausted.\n");
                return NULL;
        }
        
        prelude_list_init(&rule->rule_list);
        prelude_list_init(&rule->regex_list);
        prelude_list_init(&rule->operation_list);
                
        return rule;
}



static void free_rule(pcre_rule_t *rule) 
{
        rule_regex_t *item;
        prelude_list_t *tmp, *bkp;
        pcre_rule_container_t *rc;
        
        prelude_list_for_each_safe(&rule->rule_list, tmp, bkp) {
                rc = prelude_list_entry(tmp, pcre_rule_container_t, list);
                free_rule_container(rc);
        }
        
        prelude_list_for_each_safe(&rule->regex_list, tmp, bkp) {
                item = prelude_linked_object_get_object(tmp);
                rule_regex_destroy(item);
        }

        free_operation(&rule->operation_list);
        free(rule);
}



static void free_rule_container(pcre_rule_container_t *rc)
{
        if ( --rc->rule->refcount == 0 )
                free_rule(rc->rule);
        
        prelude_list_del(&rc->list);
        free(rc);
}



static int add_rule(pcre_plugin_t *plugin, prelude_list_t *head, pcre_rule_t *rule)
{
        pcre_rule_container_t *rc;
        
        rc = create_rule_container(rule);
        if ( ! rc ) {
                free_rule(rule);
                return -1;
        }

        if ( plugin->last_rules_first && rule->flags & PCRE_RULE_FLAGS_LAST )
                prelude_list_add(head, &rc->list);
        else
                prelude_list_add_tail(head, &rc->list);
        
        plugin->rulesnum++;

        return 0;
}



static int parse_ruleset(prelude_list_t *head, pcre_plugin_t *plugin, pcre_rule_t *rule,
                         prelude_list_t *operation_list, const char *filename, unsigned int *line, FILE *fd) 
{
        int ret;
        prelude_bool_t need_add = FALSE;
        char *operation, *variable, *value;
        
        do {
                ret = pcre_parse(fd, filename, line, &operation, &variable, &value);                
                if ( ret < 0 ) {
                        prelude_log(PRELUDE_LOG_WARN, "%s:%u: parse error: %s.\n", filename, *line, prelude_strerror(ret));
                        return ret;
                }
                
                if ( ret == 0 ) {
                        if ( rule && need_add ) {
                                need_add = FALSE;
                                add_rule(plugin, head, rule);
                        }
                        
                        return ret;
                }
                
                if ( operation && (strcmp(operation, "pattern") == 0 || strcmp(operation, "schedule") == 0) ) {       
                        if ( rule && need_add ) {
                                add_rule(plugin, head, rule);
                                need_add = FALSE;
                        }
                        
                        rule = create_rule();
                        if ( ! rule )
                                return -1;

                        if ( strcmp(operation, "schedule") != 0 )
                                need_add = TRUE;
                        
                        operation_list = &rule->operation_list;
                }
                                
                ret = parse_rule_operation(fd, filename, line, plugin, rule, operation_list, operation, variable, value);
                if ( ret < 0 ) {       
                        prelude_log(PRELUDE_LOG_WARN, "%s:%u: operation '%s': %s.\n",
                                    filename, *line, operation ? operation : "assign", prelude_strerror(ret));
                        return ret;
                }

                if ( operation ) free(operation);
                if ( variable ) free(variable);
                if ( value ) free(value);
                
        } while ( TRUE );
}


static void pcre_run(prelude_plugin_instance_t *pi, idmef_message_t *idmef)
{
        int ret;
        prelude_list_t *tmp;
        pcre_plugin_t *plugin;
        pcre_rule_container_t *rc;
        pcre_match_flags_t flags, all_flags = 0;
        
        plugin = prelude_plugin_instance_get_plugin_data(pi);

        prelude_list_for_each(&plugin->rule_list, tmp) {
                rc = prelude_list_entry(tmp, pcre_rule_container_t, list);

                flags = 0;
                ret = rule_regex_match(plugin, rc, idmef, &flags);
                all_flags |= flags;
                                
                if ( ret == 0 && (rc->rule->flags & PCRE_RULE_FLAGS_LAST || flags & PCRE_MATCH_FLAGS_LAST) )
                        break;
        }
}


static void pcre_signal(prelude_plugin_instance_t *pi, int signo)
{
        if ( signo == SIGQUIT )
                pcre_context_print_all(prelude_plugin_instance_get_plugin_data(pi));
}


static int set_last_first(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        pcre_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(context);
        
        plugin->last_rules_first = TRUE;
        
        return 0;
}


static int set_dump_unmatched(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        pcre_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(context);
        
        plugin->dump_unmatched = TRUE;
        
        return 0;
}



static int set_pcre_ruleset(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context) 
{
        int ret;
        FILE *fd;
        char *ptr;
        unsigned int line = 0;
        pcre_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(context);
        
        plugin->rulesetdir = strdup(optarg);

        ptr = strrchr(plugin->rulesetdir, '/');
        if ( ptr )
                *ptr = '\0';
        else {
                free(plugin->rulesetdir);
                plugin->rulesetdir = NULL;
        }
        
        fd = fopen(optarg, "r");
        if ( ! fd ) {
                prelude_string_sprintf(err, "couldn't open %s for reading: %s", optarg, strerror(errno));
                return -1;
        }

        ret = parse_ruleset(&plugin->rule_list, plugin, NULL, NULL, optarg, &line, fd);
        
        fclose(fd);
        if ( plugin->rulesetdir )
                free(plugin->rulesetdir);
        
        if ( ret < 0 )
                return -1;

        prelude_log(PRELUDE_LOG_INFO, "- pcre plugin loaded %d rules, restored %d context.\n",
                    plugin->rulesnum, plugin->restored_context_count);
                
        return 0;
}



static int pcre_activate(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        pcre_plugin_t *new;
        
        new = calloc(1, sizeof(*new));
        if ( ! new )
                return prelude_error_from_errno(errno);

        prelude_list_init(&new->rule_list);
        prelude_list_init(&new->context_list);
        prelude_list_init(&new->schedule_list);
        prelude_plugin_instance_set_plugin_data(context, new);
        
        pcre_context_restore(context, &new->restored_context_count);
        
        return 0;
}




static void pcre_destroy(prelude_plugin_instance_t *pi, prelude_string_t *err)
{
        struct schedule_cb *scb;
        prelude_list_t *tmp, *bkp;
        pcre_rule_container_t *rule;
        pcre_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(pi);

        pcre_context_save(pi, plugin);
        
        prelude_list_for_each_safe(&plugin->rule_list, tmp, bkp) {
                rule = prelude_list_entry(tmp, pcre_rule_container_t, list);
                free_rule_container(rule);
        }

        if ( ! prelude_list_is_empty(&plugin->schedule_list) )
                prelude_timer_destroy(&plugin->schedule_timer);
        
        prelude_list_for_each_safe(&plugin->schedule_list, tmp, bkp) {
                scb = prelude_list_entry(tmp, struct schedule_cb, list);

                free_rule(scb->rule);
                
                prelude_list_del(&scb->list);
                free(scb);
        }

        free(plugin);
}



prelude_list_t *pcre_plugin_get_context_list(pcre_plugin_t *plugin)
{
        return &plugin->context_list;
}



int pcre_operation_execute(pcre_plugin_t *plugin, pcre_rule_t *rule,
                           prelude_list_t *operation_list, idmef_message_t *input, capture_string_t *capture)
{
        int ret;
        pcre_operation_t *op;
        prelude_list_t *tmp, context_result;
        
        prelude_list_for_each(operation_list, tmp) {
                op = prelude_linked_object_get_object(tmp);
                
                prelude_list_init(&context_result);                
                ret = op->op(plugin, rule, input, capture, op->extra, &context_result);
                
                prelude_log_debug(4, "[op=%p] operation returned %d: %s.\n", op, ret,
                                  (ret < 0) ? "abording" : "continuing");
                if ( ret < 0 )
                        return -1;
        }

        return 0;
}



int pcre_LTX_correlation_plugin_init(prelude_plugin_entry_t *pe, void *root_optlist)
{
        int ret;
        prelude_option_t *opt, *popt;
        int hook = PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG;
        
        ret = prelude_option_add(root_optlist, &opt, hook, 0, "pcre", "Pcre plugin option",
                                 PRELUDE_OPTION_ARGUMENT_OPTIONAL, pcre_activate, NULL);
        if ( ret < 0 )
                return ret;
        
        prelude_plugin_set_activation_option(pe, opt, NULL);
        
        ret = prelude_option_add(opt, NULL, hook, 'r', "ruleset", "Ruleset to use",
                                 PRELUDE_OPTION_ARGUMENT_REQUIRED, set_pcre_ruleset, NULL);
        if ( ret < 0 )
                return ret;
        
        ret = prelude_option_add(opt, &popt, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG, 'l',
                                 "last-first", "Process rules with the \"last\" attribute first",
                                 PRELUDE_OPTION_ARGUMENT_NONE, set_last_first, NULL);
        if ( ret < 0 )
                return ret;
        prelude_option_set_priority(popt, PRELUDE_OPTION_PRIORITY_FIRST);

        ret = prelude_option_add(opt, &popt, PRELUDE_OPTION_TYPE_CLI, 0,
                                 "dump-unmatched", "Dump unmatched log entry",
                                 PRELUDE_OPTION_ARGUMENT_NONE, set_dump_unmatched, NULL);
        if ( ret < 0 )
                return ret;

        pcre_plugin.run = pcre_run;
        prelude_plugin_set_name(&pcre_plugin, "pcre");
        prelude_plugin_set_destroy_func(&pcre_plugin, pcre_destroy);
        prelude_plugin_entry_set_plugin(pe, (void *) &pcre_plugin);
        
        correlation_plugin_set_signal_func(&pcre_plugin, pcre_signal);
        correlation_plugin_register_signal(&pcre_plugin, SIGQUIT);
        
        return 0;
}



int pcre_LTX_prelude_plugin_version(void)
{
        return PRELUDE_PLUGIN_API_VERSION;
}
