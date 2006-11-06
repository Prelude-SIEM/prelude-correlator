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
#include <sys/time.h>
#include <pcre.h>
#include <netdb.h>
#include <assert.h>

#include <libprelude/prelude-log.h>

#include "prelude-correlator.h"

#include "pcre-mod.h"
#include "pcre-context.h"
#include "rule-object.h"
#include "rule-regex.h"
#include "context-save-restore.h"


#include "pcre-parser.h"

int pcre_LTX_prelude_plugin_version(void);
int pcre_LTX_correlation_plugin_init(prelude_plugin_entry_t *pe, void *data);


struct pcre_plugin {
        int rulesnum;
        char *rulesetdir;
        int last_rules_first;
        prelude_bool_t dump_unmatched;
        
        prelude_list_t rule_list;
        prelude_list_t context_list;

        prelude_list_t schedule_list;
        prelude_timer_t schedule_timer;
};


struct action_cb {
        value_container_t *target_context;
        rule_object_list_t *object_list;
};


struct context_cb {
        value_container_t *left_value;
        value_container_t *right_value;
};


typedef enum {
        IF_OPERATOR_EQUAL   = 0x01,
        IF_OPERATOR_LOWER   = 0x02,
        IF_OPERATOR_GREATER = 0x04,
} if_operator_type_t;


struct if_cb {
        prelude_list_t list;
        prelude_list_t operation_list;

        value_container_t *vcont;
        if_operator_type_t op;
        float value;
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



static PRELUDE_LIST(chained_rule_list);
static prelude_correlator_plugin_t pcre_plugin;
static unsigned int restored_context_count = 0;



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
        int ret;
        prelude_string_t *str;
        prelude_list_t list, *tmp, *bkp;
        pcre_context_t *ctx = NULL;

        prelude_list_init(&list);
        
        ret = value_container_resolve_listed(&list, vcont, plugin, rule, capture);
        if ( ret < 0 )
                return NULL;

        prelude_list_for_each_safe(&list, tmp, bkp) {
                str = prelude_linked_object_get_object(tmp);
                
                if ( ! ctx ) 
                        ctx = pcre_context_search(plugin, prelude_string_get_string(str));

                prelude_string_destroy(str);
        
        }
                        
        return ctx;
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
        if ( ! ctx )                
                return -1;

        return 0;
}


static int op_check_not_context(pcre_plugin_t *plugin, pcre_rule_t *rule,
                                idmef_message_t *input, capture_string_t *capture, void *extra,
                                prelude_list_t *context_result)
{
        prelude_log_debug(4, "checking not context.\n");
        
        if ( lookup_context(extra, plugin, rule, capture) )
                return -1;
        
        return 0;
}



static int op_destroy_context(pcre_plugin_t *plugin, pcre_rule_t *rule,
                              idmef_message_t *input, capture_string_t *capture, void *extra,
                              prelude_list_t *context_result)
{
        int ret;
        pcre_context_t *ctx;
        prelude_string_t *str;
        prelude_list_t dlist, *tmp, *bkp;
        
        prelude_list_init(&dlist);
                
        ret = value_container_resolve_listed(&dlist, extra, plugin, rule, capture);
        if ( ret < 0 )
                return ret;

        prelude_list_for_each_safe(&dlist, tmp, bkp) {
                str = prelude_linked_object_get_object(tmp);
                
                ctx = pcre_context_search(plugin, prelude_string_get_string(str));
                if ( ! ctx )
                        continue;
                
                pcre_context_destroy(ctx);
                prelude_string_destroy(str);
        }

        return 0;
}



static int op_action_list(pcre_plugin_t *plugin, pcre_rule_t *rule,
                          idmef_message_t *input, capture_string_t *capture, void *extra,
                          prelude_list_t *context_result)
{
        int ret;
        prelude_string_t *str;
        idmef_message_t *idmef;
        pcre_context_t *ctx = NULL;
        prelude_list_t list, *tmp, *bkp;
        struct action_cb *action = extra;

        prelude_list_init(&list);
        
        ret = value_container_resolve_listed(&list, action->target_context, plugin, rule, capture);
        if ( ret < 0 )
                return -1;

        prelude_list_for_each_safe(&list, tmp, bkp) {
                str = prelude_linked_object_get_object(tmp);
                
                ctx = pcre_context_search(plugin, prelude_string_get_string(str));
                if ( ! ctx )
                        ret = pcre_context_new(&ctx, plugin, prelude_string_get_string(str), NULL);

                prelude_log_debug(3, "[%s]: running action list.\n", prelude_string_get_string(str));
                
                idmef = pcre_context_get_value_idmef(ctx);

                ret = rule_object_build_message(plugin, rule, action->object_list, &idmef, input, capture);
                if ( ret == 0 )
                        pcre_context_set_value_idmef(ctx, idmef);
                
                prelude_string_destroy(str);
        
        }
                        
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
                if ( ctx && pcre_context_get_value_idmef(ctx) ) {
                        prelude_log_debug(3, "[%s]: emit alert.\n", pcre_context_get_name(ctx));
                        correlation_alert_emit(pcre_context_get_value_idmef(ctx));
                }
                
                prelude_string_destroy(str);
        
        }
                        
        return 0;
}



static int op_check_correlation(pcre_plugin_t *plugin, pcre_rule_t *rule,
                                idmef_message_t *input, capture_string_t *capture, void *extra,
                                prelude_list_t *context_result)
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



static int op_reset_timer(pcre_plugin_t *plugin, pcre_rule_t *rule,
                          idmef_message_t *input, capture_string_t *capture, void *extra,
                          prelude_list_t *context_result)
{
        pcre_context_t *ctx;
        
        ctx = lookup_context(extra, plugin, rule, capture);
        if ( ! ctx )
                return -1;

        pcre_context_reset_timer(ctx);
                
        return 0;
}



static int op_if(pcre_plugin_t *plugin, pcre_rule_t *rule,
                 idmef_message_t *input, capture_string_t *capture, void *extra,
                 prelude_list_t *context_result)
{
        float val;
        pcre_context_t *ctx;
        prelude_bool_t ok = FALSE;
        struct if_cb *ifcb = extra;
        
        ctx = lookup_context(ifcb->vcont, plugin, rule, capture);
        if ( ! ctx )
                return -1;

        val = pcre_context_get_value_float(ctx);
        
        if ( ifcb->op & IF_OPERATOR_EQUAL && val == ifcb->value )
                ok = TRUE;

        else if ( ifcb->op & IF_OPERATOR_LOWER && val < ifcb->value )
                ok = TRUE;

        else if ( ifcb->op & IF_OPERATOR_GREATER && val > ifcb->value )
                ok = TRUE;
        
        if ( ! ok )
                return -1;
        
        return pcre_operation_execute(plugin, rule, &ifcb->operation_list, input, capture);
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
                prelude_log_debug(3, "iteration value='%s'\n", prelude_string_get_string(str));
                
                pcre_context_set_value_from_string(ctx, prelude_string_get_string(str));
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
                return 0;
        
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



static int parse_rule_id(pcre_plugin_t *plugin, pcre_rule_t *rule, prelude_list_t *operation_list, const char *variable, const char *value) 
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



static int add_goto_single(pcre_plugin_t *plugin, pcre_rule_t *rule, int id, prelude_bool_t optional)
{
        pcre_rule_container_t *new, *cur;

        cur = search_rule(&chained_rule_list, id);
        if ( ! cur ) {
                cur = search_rule(&plugin->rule_list, id);
                if ( ! cur ) {
                        prelude_log(PRELUDE_LOG_WARN, "could not find a rule with ID %d.\n", id);
                        return -1;
                }
        }
        
        new = create_rule_container(cur->rule);
        if ( ! new ) 
                return -1;

        if ( optional )
                new->optional = TRUE;
                
        prelude_list_add_tail(&rule->rule_list, &new->list);

        return 0;
}


static int add_goto(pcre_plugin_t *plugin, pcre_rule_t *rule, const char *idstr, prelude_bool_t optional)
{
        int ret, i, idmin = 0, idmax = 0;
        
        ret = sscanf(idstr, "%d-%d", &idmin, &idmax);
        if ( ret < 1 ) {
                prelude_log(PRELUDE_LOG_WARN, "could not parse goto value '%s'.\n", idstr);
                return -1;
        }

        if ( ret == 1 )
                idmax = idmin;
                
        for ( i = idmin; i <= idmax; i++ ) {
                
                ret = add_goto_single(plugin, rule, i, optional);
                if ( ret < 0 )
                        return -1;
        }

        return 0;
}


static int parse_rule_goto(pcre_plugin_t *plugin, pcre_rule_t *rule,
                           prelude_list_t *operation_list, const char *variable, const char *value)
{
        return add_goto(plugin, rule, value, FALSE);
}



static int parse_rule_optgoto(pcre_plugin_t *plugin, pcre_rule_t *rule,
                              prelude_list_t *operation_list, const char *variable, const char *value)
{
        return add_goto(plugin, rule, value, TRUE);
}



static int parse_rule_min_optgoto_match(pcre_plugin_t *plugin, pcre_rule_t *rule,
                                        prelude_list_t *operation_list, const char *variable, const char *value)
{
        rule->min_optgoto_match = atoi(value);

        return 0;
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


static int parse_rule_chained(pcre_plugin_t *plugin, pcre_rule_t *rule,
                              prelude_list_t *operation_list, const char *variable, const char *value)
{
        rule->flags |= PCRE_RULE_FLAGS_CHAINED;
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
                
                else {
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


static pcre_context_setting_t *get_last_parsed_context(pcre_rule_t *rule)
{
        prelude_list_t *tmp;
        pcre_operation_t *op;
        
        prelude_list_for_each_reversed(&rule->operation_list, tmp) {
                op = prelude_list_entry(tmp, pcre_operation_t, list);
                return op->extra;
        }

        return NULL;
}


static int parse_threshold(pcre_plugin_t *plugin, pcre_rule_t *rule,
                           prelude_list_t *operation_list, const char *variable, const char *value)
{
        pcre_context_setting_t *setting;

        setting = get_last_parsed_context(rule);
        if ( ! setting ) {
                prelude_log(PRELUDE_LOG_WARN, "'threshold' set but no context specified.\n");
                return -1;
        }

        setting->correlation_threshold = atoi(value);
        return 0;
}



static int parse_window(pcre_plugin_t *plugin, pcre_rule_t *rule,
                        prelude_list_t *operation_list, const char *variable, const char *value)
{
        pcre_context_setting_t *setting;
        
        setting = get_last_parsed_context(rule);
        if ( ! setting ) {
                prelude_log(PRELUDE_LOG_WARN, "'window' set but no context specified.\n");
                return -1;
        }
        
        setting->correlation_window = atoi(value);

        return 0;
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


static int action_parse(struct rule_object_list *object_list, const char *arg)
{
        int ret;
        char *key, *value;
        
        do {
                ret = parse_multiple_key_and_value(&arg, &key, &value);                
                if ( ret != 1 )
                        return ret;
                
                ret = rule_object_add(object_list, key, value); 
                if ( ret < 0 )
                        return ret;
        } while ( 1 );

        return 0;  
}



static void action_cb_destroy(void *data)
{
        struct action_cb *action = data;
        
        rule_object_list_destroy(action->object_list);
        value_container_destroy(action->target_context);

        free(action);
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



static int context_assign_preprocess(pcre_context_t *ctx, prelude_string_t *pstr)
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
             return pcre_context_set_value_from_string(ctx, prelude_string_get_string(pstr));

        return 0;
}



static int op_context_assign(pcre_plugin_t *plugin, pcre_rule_t *rule,idmef_message_t *input,
                             capture_string_t *capture, void *extra, prelude_list_t *context_result)
{
        int ret;
        pcre_context_t *ctx;
        prelude_string_t *str;
        prelude_list_t list, *tmp, *bkp;
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

                str = value_container_resolve(cdata->right_value, plugin, rule, capture);
                if ( ! str )
                        return -1;
                
                context_assign_preprocess(ctx, str);
                prelude_string_destroy(str);
        }
        
        return 0;
}


static void context_assign_destroy(void *data)
{
        struct context_cb *cdata = data;

        value_container_destroy(cdata->left_value);
        value_container_destroy(cdata->right_value);

        free(cdata);
}



static int parse_idmef_object_list(prelude_list_t *operation_list, value_container_t *vcont, pcre_rule_t *rule, const char *value)
{
        int ret;
        struct action_cb *action;
        struct rule_object_list *object_list;

        action = malloc(sizeof(*action));
        if ( ! action )
                return prelude_error_from_errno(errno);
        
        object_list = rule_object_list_new();
        if ( ! object_list ) {
                free(action);
                return prelude_error_from_errno(errno);
        }
        
        ret = action_parse(object_list, value);
        if ( ret < 0 ) {
                free(action);
                rule_object_list_destroy(object_list);
                return ret;
        }

        action->target_context = vcont;
        action->object_list = object_list;
        
        ret = add_operation(operation_list, op_action_list, (void *) action_cb_destroy, action);
        if ( ret < 0 ) {
                free(action);
                rule_object_list_destroy(object_list);
                return ret;
        }

        return ret;
}



static int parse_context_assign(pcre_plugin_t *plugin, pcre_rule_t *rule,
                                prelude_list_t *operation_list, const char *target, const char *arg)
{
        int ret;
        value_container_t *vcont;
        struct context_cb *cdata;
        
        ret = value_container_new(&vcont, target);        
        if ( ret < 0 )
                return ret;

        if ( strchr(arg, '=') ) {
                ret = parse_idmef_object_list(operation_list, vcont, rule, arg);
                if ( ret < 0 )
                        value_container_destroy(vcont);
                
                return ret;
        }

        cdata = malloc(sizeof(*cdata));
        cdata->left_value = vcont;
        
        ret = value_container_new(&cdata->right_value, arg);
        if ( ret < 0 ) {
                value_container_destroy(vcont);
                return ret;
        }
        
        ret = add_operation(operation_list, op_context_assign, (void *) context_assign_destroy, cdata);
        if ( ret < 0 ) {
                value_container_destroy(vcont);
                value_container_destroy(cdata->right_value);
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
        
        return pcre_context_set_value_from_string(ctx, value);
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
        free_operation(&ifcb->operation_list);
        value_container_destroy(ifcb->vcont);
        free(ifcb);
}


static int parse_if(FILE *fd, const char *filename, unsigned int *line,
                    pcre_plugin_t *plugin, pcre_rule_t *rule,
                    prelude_list_t *operation_list, const char *variable, const char *value)
{
        int ret, i;
        char *eptr;
        struct if_cb *ifcb;
        struct {
                const char *operator;
                if_operator_type_t type;
        } optbl[] = {
                { "==", IF_OPERATOR_EQUAL                     },
                { "<=", IF_OPERATOR_LOWER|IF_OPERATOR_EQUAL   },
                { ">=", IF_OPERATOR_GREATER|IF_OPERATOR_EQUAL },
                { "<", IF_OPERATOR_LOWER                      },
                { ">", IF_OPERATOR_GREATER                    },
        };
        
        ifcb = malloc(sizeof(*ifcb));
        if ( ! ifcb ) {
                prelude_log(PRELUDE_LOG_ERR, "memory exhausted.\n");
                return -1;
        }
 
        prelude_list_init(&ifcb->operation_list);
        
        ret = value_container_new(&ifcb->vcont, variable);
        if ( ret < 0 ) {
                free(ifcb);
                return -1;
        }
        
        for ( i = 0; i < sizeof(optbl) / sizeof(*optbl); i++ ) {
                if ( strncmp(value, optbl[i].operator, strlen(optbl[i].operator)) == 0 ) {
                        ifcb->op = optbl[i].type;
                        break;
                }
        }
        
        if ( i == sizeof(optbl) / sizeof(*optbl) ) {
                if_cb_destroy(ifcb);
                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "Invalid operator specified for 'if' command: '%s'", value);
        }
        
        value += strcspn(value, " ");

        ifcb->value = strtod(value, &eptr);        
        if ( eptr == value || (*eptr != ' ' && *eptr != '{') ) {
                if_cb_destroy(ifcb);
                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "Invalid value specified to 'if' command: '%s'", value);
        }
        
        ret = parse_ruleset(&rule->rule_list, plugin, rule, &ifcb->operation_list, filename, line, fd);        
        if ( ret < 0 ) {
                if_cb_destroy(ifcb);
                return ret;
        }
        
        ret = add_operation(operation_list, op_if, (void *) if_cb_destroy, ifcb);
        if ( ret < 0 ) {
                if_cb_destroy(ifcb);
                return -1;
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

        forcb->var = strdup(variable);
        if ( ! forcb->var ) {
                free(forcb);
                return prelude_error_from_errno(errno);
        }

        ptr = strstr(value, "$");
        if ( ! ptr )
                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "invalid format for 'for' operation");

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
                { "chained"             , TRUE, parse_rule_chained            },
                { "goto"                , TRUE, parse_rule_goto               },
                { "id"                  , TRUE, parse_rule_id                 },
                { "last"                , TRUE, parse_rule_last               },
                { "min-optgoto-match"   , TRUE, parse_rule_min_optgoto_match  },
                { "optgoto"             , TRUE, parse_rule_optgoto            },
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
                { "threshold"           , TRUE, parse_threshold               },
                { "window"              , TRUE, parse_window                  },
                { "pattern"             , TRUE, parse_pattern                 },
                { "alert"               , TRUE, parse_alert                   },
                { "global"              , FALSE, parse_global                 },
                { "schedule"            , FALSE, parse_schedule               },
        };

        if ( ! operation ) {
                ret = parse_context_assign(plugin, rule, operation_list, variable, value);                        
                if ( ret < 0 )
                        ret = prelude_error_verbose(PRELUDE_ERROR_GENERIC, "context assignement error: %s.\n", prelude_strerror(ret));
                
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

        if ( rule->flags & PCRE_RULE_FLAGS_CHAINED )
                prelude_list_add(&chained_rule_list, &rc->list);
        
        else if ( plugin->last_rules_first && rule->flags & PCRE_RULE_FLAGS_LAST )
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
                                    filename, *line, operation, prelude_strerror(ret));
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


static void remove_top_chained(void)
{
        prelude_list_t *tmp, *bkp;
        pcre_rule_container_t *rc;
        
        prelude_list_for_each_safe(&chained_rule_list, tmp, bkp) {
                rc = prelude_list_entry(tmp, pcre_rule_container_t, list);

                if ( rc->rule->flags & PCRE_RULE_FLAGS_CHAINED )
                        free_rule_container(rc);
        }
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
                    plugin->rulesnum, restored_context_count);

        remove_top_chained();
                
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
        
        restored_context_count = pcre_context_restore(context);
        
        return 0;
}




static void pcre_destroy(prelude_plugin_instance_t *pi, prelude_string_t *err)
{
        pcre_context_t *ctx;
        struct schedule_cb *scb;
        prelude_list_t *tmp, *bkp;
        pcre_rule_container_t *rule;
        pcre_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(pi);

        pcre_context_save_from_list(pi, plugin);
        
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
        
        return 0;
}



int pcre_LTX_prelude_plugin_version(void)
{
        return PRELUDE_PLUGIN_API_VERSION;
}
