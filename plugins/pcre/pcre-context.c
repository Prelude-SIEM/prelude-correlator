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


struct pcre_context {
        PRELUDE_LINKED_OBJECT;

        prelude_list_t intlist;
        
        char *name;
        prelude_timer_t timer;
        pcre_context_setting_t *setting;

        unsigned int threshold;

        pcre_context_type_t type;
        union {
                char *string;
                idmef_message_t *idmef;
                float val;
        } value;
};


static void _pcre_context_destroy_type(pcre_context_t *ctx)
{
        if ( ctx->type == PCRE_CONTEXT_TYPE_IDMEF )
                idmef_message_destroy(ctx->value.idmef);

        else if ( ctx->type == PCRE_CONTEXT_TYPE_STRING )
                free(ctx->value.string);
}


static void _pcre_context_destroy(pcre_context_t *ctx)
{        
        prelude_log_debug(1, "[%s]: destroying context.\n", ctx->name);

        _pcre_context_destroy_type(ctx);
                
        prelude_timer_destroy(&ctx->timer);
        prelude_list_del(&ctx->intlist);
        
        if ( ctx->setting && ctx->setting->need_destroy )
                pcre_context_setting_destroy(ctx->setting);
        
        free(ctx->name);
        free(ctx);
}



static void pcre_context_expire(void *data)
{
        pcre_context_t *ctx = data;

        if ( ctx->setting->flags & PCRE_CONTEXT_SETTING_FLAGS_ALERT_ON_EXPIRE && ctx->value.idmef ) {
                prelude_log_debug(1, "[%s]: emit alert on expire.\n", ctx->name);
                correlation_alert_emit(ctx->value.idmef);
        }
        
        _pcre_context_destroy(ctx);
}



static int parse_float_value(const char *str, float *out)
{
        float val, prev_val = 0;
        char *eptr, operator = 0;
        
        *out = 0;
        
        while ( *str ) {
                while ( isspace(*str) ) str++;
                
                val = strtod(str, &eptr);
                while ( isspace(*eptr) ) eptr++;
                
                if ( *eptr != '/' && *eptr != '-' && *eptr != '+' && *eptr != '\0' )
                        return -1;
                
                if ( operator == '-' )
                        *out -= val;

                else if ( operator == '+' )
                        *out += val;

                else if ( operator == '/' )
                        *out /= val;

                else    *out = val;
                                
                if ( *eptr == '\0' )
                        break;

                prev_val = val;
                operator = *eptr;
                str = eptr + 1;
        }

        return 0;
}


static void context_change_type_if_needed(pcre_context_t *ctx, pcre_context_type_t ntype)
{
        const char *type1, *type2;
        const char *tbl[] = { "unknown", "float", "string", "idmef" };
        
        if ( ctx->type == PCRE_CONTEXT_TYPE_UNKNOWN || ctx->type == ntype )
                return;

        type1 = (ctx->type < sizeof(tbl) / sizeof(*tbl)) ? tbl[ctx->type] : "invalid";
        type2 = (ntype < sizeof(tbl) / sizeof(*tbl)) ? tbl[ntype] : "invalid";
        
        prelude_log(PRELUDE_LOG_ERR, "[%s]: WARNING type changing from '%s' to '%s'.\n", ctx->name, type1, type2);
        _pcre_context_destroy_type(ctx);
}



void pcre_context_destroy(pcre_context_t *ctx)
{               
        if ( ctx->setting && ctx->setting->flags & PCRE_CONTEXT_SETTING_FLAGS_ALERT_ON_DESTROY && ctx->value.idmef ) {
                prelude_log_debug(1, "[%s]: emit alert on destroy.\n", ctx->name);
                correlation_alert_emit(ctx->value.idmef);
        }
        
        _pcre_context_destroy(ctx);
}



prelude_timer_t *pcre_context_get_timer(pcre_context_t *ctx)
{
        return &ctx->timer;
}


pcre_context_setting_t *pcre_context_get_setting(pcre_context_t *ctx)
{
        return ctx->setting;
}


unsigned int pcre_context_get_threshold(pcre_context_t *ctx)
{
        return ctx->threshold;
}



void pcre_context_set_threshold(pcre_context_t *ctx, unsigned int threshold)
{
        ctx->threshold = threshold;
}



const char *pcre_context_get_name(pcre_context_t *ctx)
{
        return ctx->name;
}


int pcre_context_check_correlation(pcre_context_t *ctx)
{
        pcre_context_setting_t *setting = ctx->setting;
        
        if ( ! setting )
                return 0;

        prelude_log_debug(1, "[%s]: correlation check threshold=%d required=%d.\n",
                          ctx->name, ctx->threshold + 1, setting->correlation_threshold);

        if ( setting->timeout ) {
                prelude_timer_set_expire(&ctx->timer, setting->timeout);
                prelude_timer_reset(&ctx->timer);
        }
        
        if ( setting->correlation_threshold && ++ctx->threshold != setting->correlation_threshold )
                return -1;

        return 0;
}



int pcre_context_new(pcre_context_t **out, pcre_plugin_t *plugin,
                     const char *name, pcre_context_setting_t *setting)
{
        pcre_context_t *ctx;

        if ( ! setting || ! (setting->flags & PCRE_CONTEXT_SETTING_FLAGS_QUEUE) ) {
                *out = ctx = pcre_context_search(plugin, name);
                if ( ctx ) {
                        if ( setting && setting->flags & PCRE_CONTEXT_SETTING_FLAGS_OVERWRITE ) {
                                prelude_log_debug(1, "[%s]: destroying on create (overwrite).\n", name);
                                pcre_context_destroy(ctx);
                        } else {
                                prelude_log_debug(1, "[%s]: already exist, create only specified.\n", name);
                                return -2;
                        }
                }
        }
        
        *out = ctx = calloc(1, sizeof(*ctx));
        if ( ! ctx ) {
                prelude_log(PRELUDE_LOG_ERR, "memory exhausted.\n");
                return -1;
        }

        if ( setting )
                prelude_log_debug(1, "[%s]: creating context (expire=%ds cthresh=%d).\n", name,
                                  setting->timeout, setting->correlation_threshold);
        else
                prelude_log_debug(1, "[%s]: creating context.\n", name);
                
        ctx->name = strdup(name);
        if ( ! ctx->name ) {
                free(ctx);
                prelude_log(PRELUDE_LOG_ERR, "memory exhausted.\n");
                return -1;
        }
        
        ctx->setting = setting;
        prelude_timer_init_list(&ctx->timer);
                
        if ( setting && setting->timeout > 0 ) {
                prelude_timer_set_data(&ctx->timer, ctx);
                prelude_timer_set_expire(&ctx->timer, setting->timeout);
                prelude_timer_set_callback(&ctx->timer, pcre_context_expire);
                prelude_timer_init(&ctx->timer);
        }
        
        prelude_list_add_tail(pcre_plugin_get_context_list(plugin), &ctx->intlist);
        
        return 0;
}



int pcre_context_get_value_as_string(pcre_context_t *ctx, prelude_string_t *out)
{
        int ret;

        if ( ctx->type == PCRE_CONTEXT_TYPE_UNKNOWN || ctx->type == PCRE_CONTEXT_TYPE_IDMEF )
                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "value for context '%s' is undefined", ctx->name);
        
        if ( ctx->type == PCRE_CONTEXT_TYPE_FLOAT )
                ret = prelude_string_sprintf(out, "%f", ctx->value.val);
        else
                ret = prelude_string_cat(out, ctx->value.string);

        return ret;
}



idmef_message_t *pcre_context_get_value_idmef(pcre_context_t *ctx)
{
        assert(ctx->type == PCRE_CONTEXT_TYPE_UNKNOWN || ctx->type == PCRE_CONTEXT_TYPE_IDMEF);
        return ctx->value.idmef;
}


void pcre_context_set_value_idmef(pcre_context_t *ctx, idmef_message_t *idmef)
{
        context_change_type_if_needed(ctx, PCRE_CONTEXT_TYPE_IDMEF);
        ctx->type = PCRE_CONTEXT_TYPE_IDMEF;
        
        if ( ctx->value.idmef && idmef != ctx->value.idmef )
                idmef_message_destroy(ctx->value.idmef);

        ctx->value.idmef = idmef;
}


float pcre_context_get_value_float(pcre_context_t *ctx)
{
        assert(ctx->type == PCRE_CONTEXT_TYPE_UNKNOWN || ctx->type == PCRE_CONTEXT_TYPE_FLOAT);
        return ctx->value.val;
}


void pcre_context_set_value_float(pcre_context_t *ctx, float val)
{
        context_change_type_if_needed(ctx, PCRE_CONTEXT_TYPE_FLOAT);
        
        ctx->type = PCRE_CONTEXT_TYPE_FLOAT;
        ctx->value.val = val;
}



const char *pcre_context_get_value_string(pcre_context_t *ctx)
{
        assert(ctx->type == PCRE_CONTEXT_TYPE_UNKNOWN || ctx->type == PCRE_CONTEXT_TYPE_STRING);
        return ctx->value.string;
}



void pcre_context_set_value_string(pcre_context_t *ctx, const char *str)
{
        context_change_type_if_needed(ctx, PCRE_CONTEXT_TYPE_STRING);

        if ( ctx->value.string )
                free(ctx->value.string);
        
        ctx->type = PCRE_CONTEXT_TYPE_STRING;
        ctx->value.string = strdup(str);
}



int pcre_context_set_value_from_string(pcre_context_t *ctx, const char *str)
{
        int ret;
        float val;

        ret = parse_float_value(str, &val);
        if ( ret == 0 ) {
                prelude_log_debug(3, "[%s]: set value float: '%s' = %f.\n", ctx->name, str, val);
                pcre_context_set_value_float(ctx, val);
        } else {
                prelude_log_debug(3, "[%s]: set value string: '%s'.\n", ctx->name, str);
                pcre_context_set_value_string(ctx, str);
        }
                
        return 0;
}



pcre_context_t *pcre_context_search(pcre_plugin_t *plugin, const char *name)
{
        pcre_context_t *ctx;
        prelude_list_t *tmp;
        
        prelude_list_for_each(pcre_plugin_get_context_list(plugin), tmp) {
                ctx = prelude_list_entry(tmp, pcre_context_t, intlist);
                
                if ( strcmp(ctx->name, name) == 0 )
                        return ctx;
        }
        
        return NULL;
}



int pcre_context_search_regex(prelude_list_t *outlist, pcre_plugin_t *plugin, const pcre *regex)
{
        int ret, i = 0;
        pcre_context_t *ctx;
        prelude_list_t *tmp;
        
        prelude_list_for_each(pcre_plugin_get_context_list(plugin), tmp) {
                ctx = prelude_list_entry(tmp, pcre_context_t, intlist);

                ret = pcre_exec(regex, NULL, ctx->name, strlen(ctx->name), 0, 0, NULL, 0);
                if ( ret == 0 ) {
                        i++;
                        prelude_linked_object_add(outlist, (prelude_linked_object_t *) ctx);
                }
        }
        
        return i;
}



void pcre_context_setting_destroy(pcre_context_setting_t *settings)
{
        if ( settings->vcont )
                value_container_destroy(settings->vcont);

        free(settings);
}



void pcre_context_reset_timer(pcre_context_t *ctx)
{
        prelude_timer_set_expire(&ctx->timer, ctx->setting->timeout);
        prelude_timer_reset(&ctx->timer);
}



pcre_context_type_t pcre_context_get_type(pcre_context_t *ctx)
{
        return ctx->type;
}



void pcre_context_save_from_list(prelude_plugin_instance_t *pi, pcre_plugin_t *plugin)
{
        pcre_context_t *ctx;
        prelude_list_t *tmp, *bkp;
        
        prelude_list_for_each_safe(pcre_plugin_get_context_list(plugin), tmp, bkp) {
                ctx = prelude_list_entry(tmp, pcre_context_t, intlist);
                pcre_context_save(pi, ctx);
        }
}
