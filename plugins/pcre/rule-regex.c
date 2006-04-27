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
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/time.h>
#include <pcre.h>
#include <netdb.h>
#include <assert.h>

#include <libprelude/idmef.h>
#include <libprelude/prelude-log.h>
#include <libprelude/prelude-inttypes.h>
#include <libprelude/prelude-linked-object.h>

#include "prelude-correlator.h"
#include "pcre-mod.h"
#include "rule-object.h"
#include "rule-regex.h"



#ifndef MIN
# define MIN(x, y) (((x) < (y)) ? (x) : (y))
#endif

#ifndef MAX
# define MAX(x, y) (((x) > (y)) ? (x) : (y))
#endif


struct rule_regex {
        PRELUDE_LINKED_OBJECT;

        idmef_path_t *path;
        
        pcre *regex;
        pcre_extra *extra;
        char *regex_string;
};


typedef struct {
        idmef_message_t *idmef;
} pcre_state_t;



/*
 * In a match where some of the capture are not required, pcre_exec will
 * not always return the _full_ number of captured substring. This function
 * make sure that all not captured substring are set to -1, and then return
 * the total of substring, including the one that were not captured.
 */
static int do_pcre_exec(rule_regex_t *item, int *real_ret,
                        const char *subject, size_t length, int *ovector, int osize)
{
        int cnt = 0, i;
        
        *real_ret = pcre_exec(item->regex, item->extra, subject, length, 0, 0, ovector, osize);
        
        prelude_log_debug(9, "match %s ret %d\n", item->regex_string, *real_ret);
        
        if ( *real_ret <= 0 )
                return *real_ret;
        
        pcre_fullinfo(item->regex, item->extra, PCRE_INFO_CAPTURECOUNT, &cnt);
        if ( cnt == 0 )
                return *real_ret;

        for ( i = (*real_ret * 2); (i + 2) < (MIN(osize, cnt + 1) * 2); i += 2 )
                ovector[i] = ovector[i + 1] = -1;
                        
        return cnt + 1;
}



static int listed_value_cb(idmef_value_t *value, void *extra)
{
        int ret;
        
        if ( ! prelude_string_is_empty(extra) )
                prelude_string_cat(extra, ",");
        
        ret = idmef_value_to_string(value, extra);
        if ( ret < 0 ) {
                prelude_perror(ret, "error converting value to string");
                return ret;
        }

        return ret;
}



static int get_regex_subject(rule_regex_t *regex, idmef_message_t *idmef, prelude_string_t *outstr)
{
        int ret;
        idmef_value_t *value;
        
        ret = idmef_path_get(regex->path, idmef, &value);
        if ( ret < 0 ) {
                prelude_perror(ret, "error retrieving path '%s'", idmef_path_get_name(regex->path, -1));
                return ret;
        }

        else if ( ret == 0 )
                prelude_string_set_constant(outstr, "");

        else if ( idmef_value_is_list(value) ) {
                printf("VALUE IS LIST\n");
                idmef_value_iterate(value, listed_value_cb, outstr);
                
        } else {     
                ret = idmef_value_to_string(value, outstr);
                idmef_value_destroy(value);
                
                if ( ret < 0 ) {
                        prelude_perror(ret, "error converting value to string");
                        return ret;
                }
        }

        return 0;
}



static int exec_regex(pcre_rule_t *rule, idmef_message_t *input,
                      char **capture, size_t *capture_size)
{
        char buf[1024];
        rule_regex_t *item;
        prelude_list_t *tmp;
        prelude_string_t *subject;
        size_t max_capsize = *capture_size;
        int ovector[MAX_REFERENCE_PER_RULE * 3], osize = sizeof(ovector) / sizeof(int), real_ret, ret, i = 0;

        *capture_size = 0;
        
        ret = prelude_string_new(&subject);
        if ( ret < 0 )
                return ret;
        
        prelude_list_for_each(&rule->regex_list, tmp) {
                item = prelude_linked_object_get_object(tmp);

                ret = get_regex_subject(item, input, subject);
                if ( ret < 0 ) {
                        prelude_string_destroy(subject);
                        return ret;
                }

                ret = do_pcre_exec(item, &real_ret, prelude_string_get_string(subject),
                                   prelude_string_get_len(subject), ovector, osize);
                
                prelude_log_debug(5, "id=%d regex=%s path=%s value=%s ret=%d (real=%d)\n", rule->id, item->regex_string,
                                  idmef_path_get_name(item->path, -1), prelude_string_get_string(subject), ret, real_ret);
                if ( ret < 0 ) {
                        prelude_string_destroy(subject);
                        return -1;
                }
                                
                for ( i = 1; i < ret && *capture_size < max_capsize; i++ ) {                        
                        pcre_copy_substring(prelude_string_get_string(subject), ovector, real_ret, i, buf, sizeof(buf));

                        prelude_log_debug(5, "capture[%d] = %s\n", *capture_size, buf);
                        capture[(*capture_size)++] = strdup(buf);
                }

                prelude_string_clear(subject);
        }

        prelude_string_destroy(subject);
        return *capture_size;
}



static pcre_context_t *lookup_context(value_container_t *vcont, pcre_plugin_t *plugin,
                                      pcre_rule_t *rule, char **capture, size_t capture_size)
{
        pcre_context_t *ctx;
        prelude_string_t *str;
        
        str = value_container_resolve(vcont, rule, capture, capture_size);
        if ( ! str )
                return NULL;
        
        ctx = pcre_context_search(plugin, prelude_string_get_string(str));        
        prelude_string_destroy(str);
                
        return ctx;
}


static void free_capture(char **capture, size_t capture_size)
{
        size_t i;

        for ( i = 0; i < capture_size; i++ )
                free(capture[i]);
}


static void create_context_if_needed(pcre_context_t **used_ctx, value_container_t **used_vcont,
                                     pcre_plugin_t *plugin, pcre_rule_t *rule,
                                     pcre_state_t *state, char **capture, size_t capture_size)
{
        prelude_list_t *tmp;
        prelude_string_t *str;
        value_container_t *vcont;
        pcre_context_setting_t *pcs;
        
        prelude_list_for_each(&rule->create_context_list, tmp) {
                vcont = prelude_linked_object_get_object(tmp);
                        
                str = value_container_resolve(vcont, rule, capture, capture_size);
                if ( ! str )
                        continue;

                pcs = value_container_get_data(vcont);
                        
                pcre_context_new(used_ctx, plugin, prelude_string_get_string(str), state->idmef, pcs);
                prelude_string_destroy(str);

                *used_vcont = vcont;
        }
}



static int check_context(pcre_context_t **used_context, value_container_t **used_vcont,
                         pcre_plugin_t *plugin, pcre_rule_t *rule, pcre_state_t *state,
                         idmef_message_t *input, char **capture, size_t csize)
{
        prelude_list_t *tmp;
        value_container_t *vcont;
        pcre_context_t *ctx = NULL;
        
        *used_vcont = NULL;
        *used_context = NULL;
        
        prelude_list_for_each(&rule->not_context_list, tmp) {
                vcont = prelude_linked_object_get_object(tmp);
                if ( lookup_context(vcont, plugin, rule, capture, csize) )
                        return -1;
        }
                
        if ( rule->required_context ) {
                ctx = lookup_context(rule->required_context, plugin, rule, capture, csize);                
                if ( ! ctx )
                        return -1;
                
                state->idmef = idmef_message_ref(pcre_context_get_idmef(ctx));
                *used_vcont = rule->required_context;
        }

        if ( rule->optional_context ) {
                ctx = lookup_context(rule->optional_context, plugin, rule, capture, csize);
                if ( ctx )                
                        state->idmef = idmef_message_ref(pcre_context_get_idmef(ctx));

                *used_vcont = rule->optional_context;
        }

        *used_context = ctx;
        return 0;
}



static void destroy_idmef_state(pcre_state_t *state)
{
        if ( state->idmef ) {
                idmef_message_destroy(state->idmef);
                state->idmef = NULL;
        }
}




static void destroy_context_if_needed(pcre_plugin_t *plugin, pcre_rule_t *rule, char **capture, size_t capture_size)
{
        pcre_context_t *ctx;
        prelude_list_t *tmp;
        prelude_string_t *str;
        value_container_t *vcont;
        
        prelude_list_for_each(&rule->destroy_context_list, tmp) {
                vcont = prelude_linked_object_get_object(tmp);
                
                str = value_container_resolve(vcont, rule, capture, capture_size);
                if ( ! str )
                        continue;

                ctx = pcre_context_search(plugin, prelude_string_get_string(str));
                if ( ! ctx )
                        continue;
                
                pcre_context_destroy(ctx);
                prelude_string_destroy(str);
        }
}



static int match_rule_list(pcre_plugin_t *plugin,
                           pcre_rule_container_t *rc, pcre_state_t *state,
                           idmef_message_t *input,
                           pcre_match_flags_t *match_flags)
{        
        prelude_list_t *tmp;
        int ret, optmatch = 0;
        pcre_match_flags_t gl = 0;
        pcre_context_t *ctx = NULL;
        pcre_rule_t *rule = rc->rule;
        pcre_rule_container_t *child;
        value_container_t *vcont = NULL;
        char *capture[MAX_REFERENCE_PER_RULE];
        size_t capture_size = MAX_REFERENCE_PER_RULE;
        
        ret = exec_regex(rule, input, capture, &capture_size);
        if ( ret < 0 ) {
                free_capture(capture, capture_size);
                return -1;
        }
        
        prelude_list_for_each(&rule->rule_list, tmp) {
                child = prelude_list_entry(tmp, pcre_rule_container_t, list);
                
                ret = match_rule_list(plugin, child, state, input, &gl);
                if ( ret < 0 && ! child->optional ) {
                        destroy_idmef_state(state);
                        free_capture(capture, capture_size);
                        return -1;
                }

                if ( child->optional )
                        optmatch++;
                
                *match_flags |= gl;
                if ( gl & PCRE_MATCH_FLAGS_LAST )
                        break;
        }
                
        if ( optmatch < rule->min_optgoto_match ) {
                destroy_idmef_state(state);
                free_capture(capture, capture_size);
                return -1;
        }

        /*
         * Current rule and sub-rules matched, verify contexts.
         */
        ret = check_context(&ctx, &vcont, plugin, rule, state, input, capture, capture_size);
        if ( ret < 0 ) {
                destroy_idmef_state(state);
                free_capture(capture, capture_size);
                return -1;
        }

        /*
         * Context verification succeeded, build the pre_action stuff.
         */
        ret = rule_object_build_message(rule, rule->pre_action_object_list, &state->idmef, input, capture, capture_size);
        if ( ret < 0 ) {
                destroy_idmef_state(state);
                free_capture(capture, capture_size);
                return ret;
        }
        
        create_context_if_needed(&ctx, &vcont, plugin, rule, state, capture, capture_size);
        
        if ( ctx && vcont ) {
                ret = pcre_context_check_correlation(ctx, value_container_get_data(vcont));
                if ( ret < 0 ) {
                        destroy_idmef_state(state);
                        free_capture(capture, capture_size);
                        return -1;
                }
        }
        
        ret = rule_object_build_message(rule, rule->action_object_list, &state->idmef, input, capture, capture_size);
        if ( ret < 0 ) {
                destroy_idmef_state(state);
                free_capture(capture, capture_size);
                return ret;
        }
        
        if ( ! (rule->flags & PCRE_RULE_FLAGS_SILENT) && state->idmef ) {                
                prelude_log_debug(4, "lml alert emit id=%d (last=%d)\n",
                                  rule->id, rule->flags & PCRE_RULE_FLAGS_LAST);

                correlation_alert_emit(state->idmef);
                destroy_idmef_state(state);
                
                *match_flags |= PCRE_MATCH_FLAGS_ALERT;

                if ( rule->flags & PCRE_RULE_FLAGS_LAST )
                        *match_flags |= PCRE_MATCH_FLAGS_LAST;
        }
        
        destroy_context_if_needed(plugin, rule, capture, capture_size);
        free_capture(capture, capture_size);
        
        return 0;
}



int rule_regex_match(pcre_plugin_t *plugin, pcre_rule_container_t *root,
                     idmef_message_t *input, pcre_match_flags_t *match_flags)
{
        int ret;
        pcre_state_t state;
        
        memset(&state, 0, sizeof(state));
        
        ret = match_rule_list(plugin, root, &state, input, match_flags);
                
        if ( state.idmef )
                idmef_message_destroy(state.idmef);

        return ret;
}



rule_regex_t *rule_regex_new(const char *path, const char *regex) 
{
        int ret;
        int err_offset;
        rule_regex_t *new;
        const char *err_ptr;

        new = calloc(1, sizeof(*new));
        if ( ! new ) {
                prelude_log(PRELUDE_LOG_ERR, "memory exhausted.\n");
                return NULL;
        }
        prelude_list_init(&new->_list);

        ret = idmef_path_new(&new->path, "alert.%s", path);
        if ( ret < 0 ) {
                prelude_perror(ret, "unable to create IDMEF path '%s'", path);
                new->path = NULL;
                rule_regex_destroy(new);
                return NULL;
        }
        
        new->regex = pcre_compile(regex, 0, &err_ptr, &err_offset, NULL);
        if ( ! new->regex ) {
                prelude_log(PRELUDE_LOG_WARN, "unable to compile regex: %s.\n", err_ptr);
                rule_regex_destroy(new);
                return NULL;
        }

        new->regex_string = strdup(regex);
        if ( ! new->regex_string ) {
                prelude_log(PRELUDE_LOG_ERR, "memory exhausted.\n");
                rule_regex_destroy(new);
                return NULL;
        }

        new->extra = pcre_study(new->regex, 0, &err_ptr);
        
        return new;
}



void rule_regex_destroy(rule_regex_t *ptr)
{        
        if ( ptr->path )
                idmef_path_destroy(ptr->path);
        
        if ( ptr->regex_string )
                free(ptr->regex_string);

        if ( ptr->regex )
                pcre_free(ptr->regex);

        if ( ptr->extra )
                pcre_free(ptr->extra);

        prelude_linked_object_del((prelude_linked_object_t *) ptr);
        free(ptr);
}
