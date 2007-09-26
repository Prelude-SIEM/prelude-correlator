/*****
*
* Copyright (C) 2006,2007 PreludeIDS Technologies. All Rights Reserved.
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
#include <pcre.h>
#include <assert.h>

#include <libprelude/prelude.h>
#include <libprelude/prelude-log.h>
#include <libprelude/prelude-extract.h>
#include <libprelude/idmef-message-print.h>

#include "prelude-correlator.h"
#include "pcre-mod.h"
#include "pcre-context.h"
#include "rule-object.h"
#include "rule-regex.h"


#define CONTEXT_SETTINGS_TAG_TIMEOUT               2
#define CONTEXT_SETTINGS_TAG_FLAGS                 3
#define CONTEXT_SETTINGS_TAG_CORRELATION_WINDOW    4
#define CONTEXT_SETTINGS_TAG_CORRELATION_THRESHOLD 5
#define CONTEXT_SETTINGS_TAG_UNIQUE_PATH          11

#define CONTEXT_TIMER_TAG_ELAPSED                  6
#define CONTEXT_TIMER_TAG_SHUTDOWN                 7

#define CONTEXT_TAG_NAME                           0
#define CONTEXT_TAG_THRESHOLD                      1
#define CONTEXT_TAG_VALUE_IDMEF                    8
#define CONTEXT_TAG_VALUE_STRING                   9
#define CONTEXT_TAG_VALUE_FLOAT                   10
#define CONTEXT_TAG_UNIQUE_COUNT                  12




struct pcre_context {
        PRELUDE_LINKED_OBJECT;

        prelude_list_t intlist;

        char *name;
        prelude_timer_t timer;
        pcre_context_setting_t *setting;

        unsigned int threshold;
        unsigned int unique_count;

        pcre_context_type_t type;
        union {
                char *string;
                idmef_message_t *idmef;
                float val;
        } value;
};



static void compute_next_expire(prelude_timer_t *timer, unsigned long offtime, unsigned long elapsed)
{
        if ( offtime + elapsed > prelude_timer_get_expire(timer) )
                prelude_timer_set_expire(timer, 0);
        else
                prelude_timer_set_expire(timer, prelude_timer_get_expire(timer) - (offtime + elapsed));

        prelude_timer_reset(timer);
}




static int read_context(pcre_context_t **ctx, pcre_plugin_t *plugin, prelude_msg_t *msg)
{
        int ret;
        void *buf;
        uint8_t tag;
        uint32_t len;
        float float_val = 0;
        idmef_message_t *idmef = NULL;
        pcre_context_setting_t *settings;
        const char *name = NULL, *string_val = NULL, *unique_path = NULL;
        uint32_t threshold = 0, elapsed = 0, shutdown = 0, unique_count = 0;
        pcre_context_type_t type = PCRE_CONTEXT_TYPE_UNKNOWN;

        settings = calloc(1, sizeof(*settings));
        if ( ! settings )
                return -1;

        settings->need_destroy = TRUE;

        while ( prelude_msg_get(msg, &tag, &len, &buf) >= 0 ) {

                switch (tag) {

                case CONTEXT_TAG_NAME:
                        ret = prelude_extract_characters_safe(&name, buf, len);
                        if ( ret < 0 )
                                goto err;

                        break;

                case CONTEXT_TAG_THRESHOLD:
                        ret = prelude_extract_uint32_safe(&threshold, buf, len);
                        if ( ret < 0 )
                                goto err;

                        break;

                case CONTEXT_TAG_UNIQUE_COUNT:
                        ret = prelude_extract_uint32_safe(&unique_count, buf, len);
                        if ( ret < 0 )
                                goto err;

                        break;

                case CONTEXT_SETTINGS_TAG_TIMEOUT:
                        ret = prelude_extract_int32_safe(&settings->timeout, buf, len);
                        if ( ret < 0 )
                                goto err;

                        break;

                case CONTEXT_SETTINGS_TAG_FLAGS:
                        ret = prelude_extract_uint32_safe(&settings->flags, buf, len);
                        if ( ret < 0 )
                                goto err;

                        break;

                case CONTEXT_SETTINGS_TAG_CORRELATION_WINDOW:
                        ret = prelude_extract_uint32_safe(&settings->correlation_window, buf, len);
                        if ( ret < 0 )
                                goto err;

                        break;

                case CONTEXT_SETTINGS_TAG_CORRELATION_THRESHOLD:
                        ret = prelude_extract_uint32_safe(&settings->correlation_threshold, buf, len);
                        if ( ret < 0 )
                                goto err;

                        break;

                case CONTEXT_SETTINGS_TAG_UNIQUE_PATH:
                        ret = prelude_extract_characters_safe(&unique_path, buf, len);
                        if ( ret < 0 )
                                goto err;

                        break;

                case CONTEXT_TIMER_TAG_ELAPSED:
                        ret = prelude_extract_uint32_safe(&elapsed, buf, len);
                        if ( ret < 0 )
                                goto err;

                        break;

                case CONTEXT_TIMER_TAG_SHUTDOWN:
                        ret = prelude_extract_uint32_safe(&shutdown, buf, len);
                        if ( ret < 0 )
                                goto err;

                        break;

                case CONTEXT_TAG_VALUE_FLOAT:
                        ret = prelude_extract_float_safe(&float_val, buf, len);
                        if ( ret < 0 )
                                goto err;

                        type = PCRE_CONTEXT_TYPE_FLOAT;
                        break;

                case CONTEXT_TAG_VALUE_STRING:
                        ret = prelude_extract_characters_safe(&string_val, buf, len);
                        if ( ret < 0 )
                                goto err;

                        type = PCRE_CONTEXT_TYPE_STRING;
                        break;

                case CONTEXT_TAG_VALUE_IDMEF:
                        ret = idmef_message_new(&idmef);
                        if ( ret < 0 )
                                goto err;

                        idmef_message_set_pmsg(idmef, prelude_msg_ref(msg));

                        ret = idmef_message_read(idmef, msg);
                        if ( ret < 0 ) {
                                idmef_message_destroy(idmef);
                                goto err;
                        }

                        type = PCRE_CONTEXT_TYPE_IDMEF;
                        break;

                default:
                        ret = -1;
                        goto err;
                }
        }

        if ( ! name ) {
                free(settings);
                return -1;
        }

        ret = pcre_context_new(ctx, plugin, name, settings);
        if ( ret < 0 ) {
                free(settings);
                return ret;
        }

        if ( unique_path )
                ret = idmef_path_new(&settings->unique_path, unique_path);

        if ( type == PCRE_CONTEXT_TYPE_IDMEF )
                pcre_context_set_value_idmef(*ctx, idmef);

        else if ( type == PCRE_CONTEXT_TYPE_FLOAT )
                pcre_context_set_value_float(*ctx, float_val);

        else if ( type == PCRE_CONTEXT_TYPE_STRING )
                pcre_context_set_value_string(*ctx, string_val);

        (*ctx)->unique_count = unique_count;
        pcre_context_set_threshold(*ctx, (unsigned int) threshold);

        if ( settings->timeout > 0 )
                compute_next_expire(pcre_context_get_timer(*ctx), time(NULL) - shutdown, elapsed);

        return ret;

 err:
        free(settings);
        return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "error decoding value tagged %d: %s", tag, prelude_strerror(ret));
}



static int write_context_settings(pcre_context_setting_t *settings, prelude_msgbuf_t *msgbuf)
{
        int ret;
        uint32_t value;
        const char *str;

        if ( ! settings )
                return 0;

        value = (uint32_t) htonl(settings->timeout);
        ret = prelude_msgbuf_set(msgbuf, CONTEXT_SETTINGS_TAG_TIMEOUT, sizeof(value), &value);
        if ( ret < 0 )
                return ret;

        value = (uint32_t) htonl(settings->flags);
        ret = prelude_msgbuf_set(msgbuf, CONTEXT_SETTINGS_TAG_FLAGS, sizeof(value), &value);
        if ( ret < 0 )
                return ret;

        value = (uint32_t) htonl(settings->correlation_window);
        ret = prelude_msgbuf_set(msgbuf, CONTEXT_SETTINGS_TAG_CORRELATION_WINDOW, sizeof(value), &value);
        if ( ret < 0 )
                return ret;

        value = (uint32_t) htonl(settings->correlation_threshold);
        ret = prelude_msgbuf_set(msgbuf, CONTEXT_SETTINGS_TAG_CORRELATION_THRESHOLD, sizeof(value), &value);
        if ( ret < 0 )
                return ret;

        if ( settings->unique_path ) {
                str = idmef_path_get_name(settings->unique_path, -1);

                ret = prelude_msgbuf_set(msgbuf, CONTEXT_SETTINGS_TAG_UNIQUE_PATH, strlen(str) + 1, str);
                if ( ret < 0 )
                        return ret;
        }

        return 0;
}



static int write_context(pcre_context_t *context, prelude_msgbuf_t *msgbuf)
{
        int ret;
        time_t now;
        uint32_t value;
        const char *cname = pcre_context_get_name(context);
        prelude_timer_t *timer = pcre_context_get_timer(context);

        ret = prelude_msgbuf_set(msgbuf, CONTEXT_TAG_NAME, strlen(cname) + 1, cname);
        if ( ret < 0 )
                return ret;

        now = time(NULL);

        value = (uint32_t) htonl(pcre_context_get_threshold(context));
        ret = prelude_msgbuf_set(msgbuf, CONTEXT_TAG_THRESHOLD, sizeof(value), &value);
        if ( ret < 0 )
                return ret;

        value = (uint32_t) htonl(context->unique_count);
        ret = prelude_msgbuf_set(msgbuf, CONTEXT_TAG_UNIQUE_COUNT, sizeof(value), &value);
        if ( ret < 0 )
                return ret;

        value = (uint32_t) htonl(now - timer->start_time);
        ret = prelude_msgbuf_set(msgbuf, CONTEXT_TIMER_TAG_ELAPSED, sizeof(value), &value);
        if ( ret < 0 )
                return ret;

        value = (uint32_t) htonl(now);
        ret = prelude_msgbuf_set(msgbuf, CONTEXT_TIMER_TAG_SHUTDOWN, sizeof(value), &value);
        if ( ret < 0 )
                return ret;

        return write_context_settings(pcre_context_get_setting(context), msgbuf);
}



static int flush_msgbuf_cb(prelude_msgbuf_t *msgbuf, prelude_msg_t *msg)
{
        int ret;

        ret = prelude_msg_write(msg, prelude_msgbuf_get_data(msgbuf));
        prelude_msg_recycle(msg);

        return ret;
}



static int context_save(pcre_context_t *context, prelude_msgbuf_t *msgbuf)
{
        int ret;

        ret = write_context(context, msgbuf);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "error writing context: %s.\n", strerror(errno));
                goto err;
        }

        if ( pcre_context_get_type(context) == PCRE_CONTEXT_TYPE_IDMEF ) {
                ret = prelude_msgbuf_set(msgbuf, CONTEXT_TAG_VALUE_IDMEF, 0, NULL);
                if ( ret < 0 ) {
                        prelude_perror(ret, "error writing IDMEF message");
                        goto err;
                }

                ret = idmef_message_write(pcre_context_get_value_idmef(context), msgbuf);
                if ( ret < 0 ) {
                        prelude_perror(ret, "error writing IDMEF message");
                        goto err;
                }
        }

        else if ( pcre_context_get_type(context) == PCRE_CONTEXT_TYPE_STRING ) {
                const char *str = pcre_context_get_value_string(context);

                ret = prelude_msgbuf_set(msgbuf, CONTEXT_TAG_VALUE_STRING, strlen(str) + 1, str);
                if ( ret < 0 ) {
                        prelude_perror(ret, "error writing IDMEF message");
                        goto err;
                }
        }

        else if ( pcre_context_get_type(context) == PCRE_CONTEXT_TYPE_FLOAT ) {
                uint32_t tmp = prelude_htonf(pcre_context_get_value_float(context));

                ret = prelude_msgbuf_set(msgbuf, CONTEXT_TAG_VALUE_FLOAT, sizeof(tmp), &tmp);
                if ( ret < 0 ) {
                        prelude_perror(ret, "error writing IDMEF message");
                        goto err;
                }
        }

        prelude_msgbuf_mark_end(msgbuf);

 err:
        return ret;
}




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



static const char *context_type_to_string(pcre_context_type_t type)
{
        const char *tbl[] = { "unknown", "float", "string", "idmef" };

        if ( type >= sizeof(tbl) / sizeof(*tbl) )
                return "invalid";

        return tbl[type];
}



static void context_change_type_if_needed(pcre_context_t *ctx, pcre_context_type_t ntype)
{
        const char *type1, *type2;

        if ( ctx->type == PCRE_CONTEXT_TYPE_UNKNOWN )
                return;

        _pcre_context_destroy_type(ctx);

        if ( ctx->type == ntype )
                return;

        type1 = context_type_to_string(ctx->type);
        type2 = context_type_to_string(ntype);

        prelude_log(PRELUDE_LOG_ERR, "[%s]: WARNING type changing from '%s' to '%s'.\n", ctx->name, type1, type2);
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


int pcre_context_check_unique_count(pcre_context_t *ctx, idmef_message_t *input)
{
        int ret;
        idmef_value_t *inv, *outv;

        if ( ! ctx->setting || ! ctx->setting->unique_path || ctx->type != PCRE_CONTEXT_TYPE_IDMEF ) {
                ret = 0;
                goto out;
        }

        ret = idmef_path_get(ctx->setting->unique_path, input, &inv);
        if ( ret <= 0 )
                goto out;

        ret = idmef_path_get(ctx->setting->unique_path, ctx->value.idmef, &outv);
        if ( ret <= 0 ) {
                idmef_value_destroy(inv);
                goto out;
        }

        ret = idmef_value_match(inv, outv, IDMEF_CRITERION_OPERATOR_EQUAL);
        idmef_value_destroy(inv);
        idmef_value_destroy(outv);

    out:
        if ( ret == 0 )
                ctx->unique_count++;

        return ret;
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

        if ( setting->correlation_threshold ) {
                if ( setting->unique_path )
                        return (ctx->unique_count == setting->correlation_threshold) ? 0 : -1;
                else
                        return (++ctx->threshold == setting->correlation_threshold) ? 0 : -1;
        }

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

        if ( ctx->type == PCRE_CONTEXT_TYPE_UNKNOWN )
                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "value for context '%s' is undefined", ctx->name);

        else if ( ctx->type == PCRE_CONTEXT_TYPE_IDMEF )
                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "IDMEF context '%s' can not be translated to string", ctx->name);

        if ( ctx->type == PCRE_CONTEXT_TYPE_FLOAT )
                ret = prelude_string_sprintf(out, "%g", ctx->value.val);
        else
                ret = prelude_string_cat(out, ctx->value.string);

        return ret;
}



idmef_message_t *pcre_context_get_value_idmef(pcre_context_t *ctx)
{
        if ( ctx->type != PCRE_CONTEXT_TYPE_IDMEF && ctx->type != PCRE_CONTEXT_TYPE_UNKNOWN )
                prelude_log(PRELUDE_LOG_ERR, "[%s]: context type '%s' is not IDMEF.\n",
                            ctx->name, context_type_to_string(ctx->type));

        assert(ctx->type == PCRE_CONTEXT_TYPE_UNKNOWN || ctx->type == PCRE_CONTEXT_TYPE_IDMEF);
        return ctx->value.idmef;
}


void pcre_context_set_value_idmef(pcre_context_t *ctx, idmef_message_t *idmef)
{
        if ( ctx->value.idmef != idmef ) {
                context_change_type_if_needed(ctx, PCRE_CONTEXT_TYPE_IDMEF);

                ctx->type = PCRE_CONTEXT_TYPE_IDMEF;
                ctx->value.idmef = idmef;
        }
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

        ctx->type = PCRE_CONTEXT_TYPE_STRING;
        ctx->value.string = strdup(str);
}



int pcre_context_set_value_from_string(pcre_plugin_t *plugin, pcre_context_t *ctx, const char *str)
{
        int ret;
        float val;
        pcre_context_t *ref;
        idmef_message_t *copy;

        ret = parse_float_value(str, &val);
        if ( ret == 0 ) {
                prelude_log_debug(3, "[%s]: set value float: '%s' = %g.\n", ctx->name, str, val);
                pcre_context_set_value_float(ctx, val);
        }

        else if ( *str == '$' ) {
                prelude_log_debug(3, "[%s]: set value idmef: '%s'.\n", ctx->name, str);

                ref = pcre_context_search(plugin, str + 1);
                if ( ! ref )
                        return ret;

                ret = idmef_message_new(&copy);
                if ( ret < 0 )
                        return ret;

                ret = idmef_message_copy(pcre_context_get_value_idmef(ref), copy);
                if ( ret < 0 )
                        return ret;

                pcre_context_set_value_idmef(ctx, copy);
        }

        else {
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



int pcre_context_search_regex(prelude_list_t *outlist, pcre_plugin_t *plugin, const char *subject)
{
        pcre *regex;
        int ret, i = 0, error_offset;
        pcre_context_t *ctx;
        prelude_list_t *tmp;
        const char *err_ptr;
        char buf[strlen(subject) + 2];

        snprintf(buf, sizeof(buf), "%s$", subject);

        regex = pcre_compile(buf, PCRE_ANCHORED, &err_ptr, &error_offset, NULL);
        if ( ! regex ) {
                prelude_log(PRELUDE_LOG_ERR, "unable to compile regex: %s.\n", err_ptr);
                return -1;
        }

        prelude_list_for_each(pcre_plugin_get_context_list(plugin), tmp) {
                ctx = prelude_list_entry(tmp, pcre_context_t, intlist);

                ret = pcre_exec(regex, NULL, ctx->name, strlen(ctx->name), 0, 0, NULL, 0);
                if ( ret == 0 ) {
                        i++;
                        prelude_linked_object_add(outlist, (prelude_linked_object_t *) ctx);
                }
        }

        pcre_free(regex);

        return i;
}



void pcre_context_setting_destroy(pcre_context_setting_t *settings)
{
        if ( settings->vcont )
                value_container_destroy(settings->vcont);

        if ( settings->unique_path )
                idmef_path_destroy(settings->unique_path);

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



int pcre_context_save(prelude_plugin_instance_t *pi, pcre_plugin_t *plugin)
{
        int ret;
        FILE *fd;
        char filename[PATH_MAX];
        pcre_context_t *ctx;
        prelude_io_t *io;
        prelude_msgbuf_t *msgbuf;
        prelude_list_t *tmp, *bkp;

        snprintf(filename, sizeof(filename), PRELUDE_CORRELATOR_CONTEXT_DIR "/pcre[%s]",
                 prelude_plugin_instance_get_name(pi));

        fd = fopen(filename, "w");
        if ( ! fd ) {
                prelude_log(PRELUDE_LOG_ERR, "error opening '%s' for writing: %s.\n", filename, strerror(errno));
                return -1;
        }

        ret = prelude_io_new(&io);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "error creating IO object: %s.\n", strerror(errno));
                return ret;
        }

        prelude_io_set_file_io(io, fd);

        ret = prelude_msgbuf_new(&msgbuf);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "error creating message buffer: %s.\n", strerror(errno));
                goto err;
        }

        prelude_msgbuf_set_data(msgbuf, io);
        prelude_msgbuf_set_callback(msgbuf, flush_msgbuf_cb);

        prelude_list_for_each_safe(pcre_plugin_get_context_list(plugin), tmp, bkp) {
                ctx = prelude_list_entry(tmp, pcre_context_t, intlist);
                context_save(ctx, msgbuf);
        }

        prelude_msgbuf_destroy(msgbuf);

 err:
        prelude_io_close(io);
        prelude_io_destroy(io);

        return -1;
}



int pcre_context_restore(prelude_plugin_instance_t *plugin, unsigned int *restored_context_count)
{
        int ret;
        FILE *fd;
        prelude_io_t *io;
        prelude_msg_t *msg;
        pcre_context_t *ctx;
        char filename[PATH_MAX];

        ret = prelude_io_new(&io);
        if ( ret < 0 )
                return ret;

        snprintf(filename, sizeof(filename), PRELUDE_CORRELATOR_CONTEXT_DIR "/pcre[%s]",
                 prelude_plugin_instance_get_name(plugin));

        fd = fopen(filename, "r");
        if ( ! fd ) {
                prelude_io_destroy(io);

                if ( errno == ENOENT )
                        return 0;

                prelude_log(PRELUDE_LOG_ERR, "could not open '%s' for reading: %s.\n", filename, strerror(errno));
                return -1;
        }

        prelude_io_set_file_io(io, fd);
        *restored_context_count = 0;

        do {
                msg = NULL;

                ret = prelude_msg_read(&msg, io);
                if ( ret < 0 ) {
                        if ( prelude_error_get_code(ret) == PRELUDE_ERROR_EOF )
                                break;

                        prelude_perror(ret, "error reading '%s'", filename);
                        continue;
                }

                ret = read_context(&ctx, prelude_plugin_instance_get_plugin_data(plugin), msg);
                prelude_msg_destroy(msg);

                if ( ret < 0 ) {
                        prelude_perror(ret, "error decoding '%s'", filename);
                        continue;
                }

                (*restored_context_count)++;
        } while (TRUE);

        prelude_io_close(io);
        prelude_io_destroy(io);

        return 0;
}



void pcre_context_print(const pcre_context_t *context)
{
        /*
         * This function is used to dump currently available context as well
         * as their value. It is triggered via a signal. We use fprintf() in
         * place of prelude_log() since the later buffer is too small to handle
         * IDMEF value.
         */
        switch (context->type) {
                case PCRE_CONTEXT_TYPE_UNKNOWN:
                        fprintf(stderr, "[%s]: type=unknown threshold=%d.\n",
                                context->name, context->threshold);
                        break;

                case PCRE_CONTEXT_TYPE_FLOAT:
                        fprintf(stderr, "[%s]: type=float value=%f threshold=%d.\n",
                                context->name, context->value.val, context->threshold);
                        break;

                case PCRE_CONTEXT_TYPE_STRING:
                        fprintf(stderr, "[%s]: type=string value=%s threshold=%d.\n",
                                context->name, context->value.string, context->threshold);
                        break;

                case PCRE_CONTEXT_TYPE_IDMEF: {
                        int ret;
                        prelude_io_t *io;

                        ret = prelude_io_new(&io);
                        if ( ret < 0 )
                                return;

                        prelude_io_set_buffer_io(io);
                        idmef_message_print(context->value.idmef, io);

                        fprintf(stderr, "[%s]: type=idmef value=%p threshold=%d:\n%s\n",
                                context->name, context->value.idmef, context->threshold, (const char *) prelude_io_get_fdptr(io));

                        prelude_io_close(io);
                        prelude_io_destroy(io);
                        break;
                }
        }
}



void pcre_context_print_all(pcre_plugin_t *plugin)
{
        pcre_context_t *ctx;
        prelude_list_t *tmp;

        prelude_list_for_each(pcre_plugin_get_context_list(plugin), tmp) {
                ctx = prelude_list_entry(tmp, pcre_context_t, intlist);
                pcre_context_print(ctx);
        }
}
