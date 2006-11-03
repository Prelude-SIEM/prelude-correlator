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



struct exec_pcre_cb_data {
        int already_in_list;
        capture_string_t *capture;
        prelude_string_t *subject;
        rule_regex_t *regex;
        pcre_rule_t *rule;
        int ovector[MAX_REFERENCE_PER_RULE * 3];
};



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



static int exec_pcre_cb(void *ptr)
{
        char buf[1024];
        int ret, real_ret, i;
        struct exec_pcre_cb_data *data = ptr;
                
        /*
         * arg:
         * - subject
         */
        
        ret = do_pcre_exec(data->regex, &real_ret, prelude_string_get_string(data->subject),
                           prelude_string_get_len(data->subject), data->ovector,
                           sizeof(data->ovector) / sizeof(*data->ovector));
        if ( ret < 0 )
                return ret;
        
        prelude_log_debug(5, "id=%d regex=%s path=%s value=%s ret=%d (real=%d)\n", data->rule->id,
                          data->regex->regex_string, idmef_path_get_name(data->regex->path, -1),
                          prelude_string_get_string(data->subject), ret, real_ret);
                        
        for ( i = 1; i < ret; i++ ) {                        
                pcre_copy_substring(prelude_string_get_string(data->subject),
                                    data->ovector, real_ret, i, buf, sizeof(buf));
                
                capture_string_add_string(data->capture, buf);
        }

        return i;
}



static int maybe_listed_value_cb(idmef_value_t *value, void *extra)
{
        int ret;
        struct exec_pcre_cb_data *data = extra;
        
        if ( idmef_value_is_list(value) ) {
                if ( data->already_in_list++ == 0 )
                        capture_string_new(data->capture, &data->capture);
                
                ret = idmef_value_iterate(value, maybe_listed_value_cb, data);

                if ( --data->already_in_list == 0 )
                        data->capture = capture_string_get_parent(data->capture);
        }

        else {
                prelude_string_clear(data->subject);
                
                ret = idmef_value_to_string(value, data->subject);
                if ( ret < 0 ) {
                        prelude_perror(ret, "error converting value to string");
                        return ret;
                }

                ret = exec_pcre_cb(extra);
        }
        

        return ret;
}




static int get_regex_subject(pcre_rule_t *rule,
                             rule_regex_t *regex, idmef_message_t *idmef,
                             capture_string_t *capture, prelude_string_t *outstr)
{
        int ret;
        idmef_value_t *value;
        struct exec_pcre_cb_data data;
        
        ret = idmef_path_get(regex->path, idmef, &value);
        if ( ret < 0 ) {
                prelude_perror(ret, "error retrieving path '%s'", idmef_path_get_name(regex->path, -1));
                return ret;
        }

        data.rule = rule;
        data.regex = regex;
        data.subject = outstr;
        data.capture = capture;
        data.already_in_list = 0;
        
        if ( ret == 0 ) {
                prelude_string_set_constant(outstr, "");
                return exec_pcre_cb(&data);
        }
        
        ret = maybe_listed_value_cb(value, &data);
        idmef_value_destroy(value);

        return ret;
}



static int exec_regex(pcre_rule_t *rule, idmef_message_t *input, capture_string_t *capture)
{
        int ret;
        rule_regex_t *item;
        prelude_list_t *tmp;
        prelude_string_t *subject;
        
        ret = prelude_string_new(&subject);
        if ( ret < 0 )
                return ret;
        
        prelude_list_for_each(&rule->regex_list, tmp) {
                item = prelude_linked_object_get_object(tmp);

                ret = get_regex_subject(rule, item, input, capture, subject);
                if ( ret < 0 ) {
                        prelude_string_destroy(subject);
                        return ret;
                }

                prelude_string_clear(subject);
        }

        prelude_string_destroy(subject);
        return 0;
}



static int match_rule_list(pcre_plugin_t *plugin,
                           pcre_rule_container_t *rc,
                           idmef_message_t *input, pcre_match_flags_t *match_flags)
{        
        prelude_list_t *tmp;
        int ret, optmatch = 0;
        pcre_match_flags_t gl = 0;
        pcre_rule_t *rule = rc->rule;
        pcre_rule_container_t *child;
        capture_string_t *capture;
        
        capture_string_new(NULL, &capture);
        
        ret = exec_regex(rule, input, capture);
        if ( ret < 0 ) {
                capture_string_destroy(capture);
                return -1;
        }
        
        prelude_list_for_each(&rule->rule_list, tmp) {
                child = prelude_list_entry(tmp, pcre_rule_container_t, list);
                
                ret = match_rule_list(plugin, child, input, &gl);
                if ( ret < 0 && ! child->optional ) {
                        capture_string_destroy(capture);
                        return -1;
                }

                if ( child->optional )
                        optmatch++;
                
                *match_flags |= gl;
                if ( gl & PCRE_MATCH_FLAGS_LAST )
                        break;
        }
        
        if ( optmatch < rule->min_optgoto_match ) {
                capture_string_destroy(capture);
                return -1;
        }

        ret = pcre_operation_execute(plugin, rule, &rule->operation_list, input, capture);
        if ( ret < 0 ) {
                capture_string_destroy(capture);
                return -1;
        }
        
        capture_string_destroy(capture);
        
        return 0;
}



int rule_regex_match(pcre_plugin_t *plugin, pcre_rule_container_t *root,
                     idmef_message_t *input, pcre_match_flags_t *match_flags)
{
        return match_rule_list(plugin, root, input, match_flags);
}



int rule_regex_new(rule_regex_t **n, const char *path, const char *regex) 
{
        int ret;
        int err_offset;
        rule_regex_t *new;
        const char *err_ptr;

        *n = new = calloc(1, sizeof(*new));
        if ( ! new )
                return prelude_error_from_errno(errno);
        
        prelude_list_init(&new->_list);
        
        ret = idmef_path_new(&new->path, "alert.%s", path);
        if ( ret < 0 ) {
                new->path = NULL;
                rule_regex_destroy(new);
                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "unable to create IDMEF path '%s'", path);
        }
        
        new->regex = pcre_compile(regex, 0, &err_ptr, &err_offset, NULL);
        if ( ! new->regex ) {
                rule_regex_destroy(new);
                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "unable to compile regex: %s", err_ptr); 
        }

        new->regex_string = strdup(regex);
        if ( ! new->regex_string ) {
                rule_regex_destroy(new);
                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "memory exhausted.\n");
        }

        new->extra = pcre_study(new->regex, 0, &err_ptr);
        
        return 0;
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
