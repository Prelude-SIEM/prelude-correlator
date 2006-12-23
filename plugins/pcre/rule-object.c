/*****
*
* Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005 PreludeIDS Technologies. All Rights Reserved.
* Author: Yoann Vandoorselaere <yoann.v@prelude-ids.com>
* Author: Nicolas Delon <nicolas.delon@prelude-ids.com>
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
#include <netdb.h>

#include <libprelude/prelude.h>
#include <libprelude/prelude-log.h>
#include <libprelude/common.h>
#include <libprelude/idmef.h>
#include <libprelude/prelude-string.h>

#include "prelude-correlator.h"
#include "pcre-mod.h"
#include "rule-object.h"
#include "value-container.h"


struct rule_object_list {
        prelude_list_t rule_object_list;
};


/*
 * List of IDMEF object set by a given rule.
 */
typedef struct {
        prelude_list_t list;
        
        idmef_path_t *object;
        value_container_t *vcont;
} rule_object_t;



static const char *str_tolower(const char *str, char *buf, size_t size)
{
        unsigned int i = 0;

        buf[0] = 0;
        
        while ( i < size ) {
                buf[i] = tolower(str[i]);

                if ( str[i] == 0 )
                        break;
                
                i++;
        }
        
        return buf;
}


static idmef_value_t *build_message_object_value(pcre_rule_t *rule, rule_object_t *rule_object, const char *valstr)
{
        int ret;
        const char *str;
        struct servent *service;
        idmef_value_t *value = NULL;
        
        str = idmef_path_get_name(rule_object->object, idmef_path_get_depth(rule_object->object) - 1);
        
        ret = strcmp(str, "port");
        if ( ret != 0 || (ret == 0 && isdigit((int) *valstr)) )
                ret = idmef_value_new_from_path(&value, rule_object->object, valstr);

        else {
                char tmp[32];
                
                service = getservbyname(str_tolower(valstr, tmp, sizeof(tmp)), NULL);
                if ( ! service ) {
                        prelude_log(PRELUDE_LOG_ERR, "could not map service '%s' in rule ID %d.\n", tmp, rule->id);
                        return NULL;
                }

                ret = idmef_value_new_uint16(&value, ntohs(service->s_port));
        }
        
        if ( ret < 0 ) {
                prelude_perror(ret, "could not create path '%s' with value '%s' in rule ID %d",
                               idmef_path_get_name(rule_object->object, -1), valstr, rule->id);
                value = NULL;
        }
        
        return value;
}



typedef struct {
        const idmef_path_t *path;
        idmef_message_t *idmef;
        idmef_value_t *value;
} match_cb_t;


static int match_iterate_cb(idmef_value_t *value, void *extra) 
{
        int ret = 0;
        match_cb_t *mcb = extra;
        
        if ( idmef_value_is_list(value) )
                return idmef_value_iterate(value, match_iterate_cb, extra);

        if ( mcb->value )
                ret = idmef_value_match(value, mcb->value, IDMEF_CRITERION_OPERATOR_EQUAL);
        
        if ( ret == 0 ) {
                ret = idmef_path_set(mcb->path, mcb->idmef, value);
                if ( ret < 0 )
                        prelude_perror(ret, "could not set output path '%s'", idmef_path_get_name(mcb->path, -1));    
        }
        
        return 0;
}



static int copy_idmef_path_if_needed(const idmef_path_t *path, idmef_message_t *input, idmef_message_t *output)
{
        int ret;
        match_cb_t mcb;
        idmef_value_t *value = NULL;

        mcb.path = path;
        mcb.value = NULL;
        mcb.idmef = output;
                        
        ret = idmef_path_get(path, input, &value);
        if ( ret == 0 )
                return 0;
             
        if ( ret < 0 ) {
                prelude_perror(ret, "could not retrieve input path '%s'", idmef_path_get_name(path, -1));  
                return -1;
        }

        /*
         * In case the target path is a list with an undefined index, we can not
         * copy the source list item one by one as each item would be subsequently
         * overwritten.
         *
         * Since we don't need to check whether the item already exist in the target
         * list in this case, we short circuit the check and directly overwrite the existing
         * list.
         */
        ret = idmef_path_get_index(path, idmef_path_get_depth(path) - 1);        
        if ( value && prelude_error_get_code(ret) == PRELUDE_ERROR_IDMEF_PATH_INDEX_UNDEFINED ) {
                                
                ret = idmef_path_set(path, output, value);
                if ( ret < 0 )
                        prelude_perror(ret, "could not set output path '%s'", idmef_path_get_name(path, -1));

                idmef_value_destroy(value);
                return ret;
        }

        ret = idmef_path_get(path, output, &mcb.value);
        if ( ret < 0 ) {
                prelude_perror(ret, "could not retrieve output path '%s'", idmef_path_get_name(path, -1));
                idmef_value_destroy(value);
                return -1;
        }

        if ( ret == 0 )
                mcb.value = NULL;
        
        ret = idmef_value_iterate(value, match_iterate_cb, &mcb);

        idmef_value_destroy(value);
        if ( mcb.value )
                idmef_value_destroy(mcb.value);

        return ret;
}



int rule_object_build_message(pcre_plugin_t *plugin, pcre_rule_t *rule,
                              rule_object_list_t *olist, idmef_message_t **message,
                              idmef_message_t *idmef_in, capture_string_t *capture)
{
        int ret;
        idmef_path_t *test;
        prelude_list_t *tmp;
        idmef_value_t *value;
        prelude_string_t *strbuf;
        rule_object_t *rule_object;
        
        if ( prelude_list_is_empty(&olist->rule_object_list) )
                return 0;
        
        if ( ! *message ) {
                ret = idmef_message_new(message);
                if ( ret < 0 )
                        return -1;
        }
        
        prelude_list_for_each(&olist->rule_object_list, tmp) {
                rule_object = prelude_list_entry(tmp, rule_object_t, list);

                strbuf = value_container_resolve(rule_object->vcont, plugin, rule, capture);
                if ( ! strbuf )
                        continue;
                
                if ( strncmp(prelude_string_get_string(strbuf), "alert", 5) == 0 )
                        ret = idmef_path_new(&test, "%s", prelude_string_get_string(strbuf));
                else
                        ret = idmef_path_new(&test, "alert.%s", prelude_string_get_string(strbuf));

                value = NULL;
                if ( ret < 0 )
                        value = build_message_object_value(rule, rule_object, prelude_string_get_string(strbuf));
                else {
                        idmef_path_destroy(test); /* use the left operand object (handling of list prepend/append). */
                        ret = copy_idmef_path_if_needed(rule_object->object, idmef_in, *message);
                }
                
                prelude_string_destroy(strbuf);
                if ( ! value )
                        continue;

                ret = idmef_path_set(rule_object->object, *message, value);

                idmef_value_destroy(value);
                value_container_reset(rule_object->vcont);

                if ( ret < 0 ) {
                        prelude_perror(ret, "idmef path set failed for %s", idmef_path_get_name(rule_object->object, -1));
                        return -1;
                }
        }
        
        return 0;
}



int rule_object_add(rule_object_list_t *olist, const char *object_name, const char *value)
{
        int ret;
        idmef_path_t *object;
        rule_object_t *rule_object;

        if ( strncmp(object_name, "alert", 5) == 0 )
                ret = idmef_path_new(&object, "%s", object_name);
        else
                ret = idmef_path_new(&object, "alert.%s", object_name);
        
        if ( ret < 0 )
                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "could not create 'alert.%s' path: %s",
                                             object_name, prelude_strerror(ret));

        rule_object = malloc(sizeof(*rule_object));
        if ( ! rule_object ) {
                idmef_path_destroy(object);
                return prelude_error_from_errno(errno);
        }
        
        rule_object->object = object;

        ret = value_container_new(&rule_object->vcont, value);
        if ( ret < 0 ) {
                idmef_path_destroy(object);
                free(rule_object);
                return -1;
        }

        prelude_list_add_tail(&olist->rule_object_list, &rule_object->list);

        return 0;
}




rule_object_list_t *rule_object_list_new(void)
{
        rule_object_list_t *olist;

        olist = malloc(sizeof(*olist));
        if ( ! olist ) {
                prelude_log(PRELUDE_LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        prelude_list_init(&olist->rule_object_list);

        return olist;
}



void rule_object_list_destroy(rule_object_list_t *olist)
{
        rule_object_t *robject;
        prelude_list_t *tmp, *bkp;
        
        prelude_list_for_each_safe(&olist->rule_object_list, tmp, bkp) {
                robject = prelude_list_entry(tmp, rule_object_t, list);

                idmef_path_destroy(robject->object);
                value_container_destroy(robject->vcont);
                
                prelude_list_del(&robject->list);
                free(robject);
        }
        
        free(olist);
}




prelude_bool_t rule_object_list_is_empty(rule_object_list_t *olist)
{
        return prelude_list_is_empty(&olist->rule_object_list);
}
