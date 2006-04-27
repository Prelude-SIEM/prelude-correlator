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
#include <sys/time.h>
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




int rule_object_build_message(pcre_rule_t *rule, rule_object_list_t *olist, idmef_message_t **message,
                              idmef_message_t *idmef_in, capture_string_t *capture)
{
        int ret;
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

                strbuf = value_container_resolve(rule_object->vcont, rule, capture);
                if ( ! strbuf )
                        continue;

                value = build_message_object_value(rule, rule_object, prelude_string_get_string(strbuf));
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



int rule_object_add(rule_object_list_t *olist,
                    const char *filename, int line,
                    const char *object_name, const char *value)
{
        int ret;
        idmef_path_t *object;
        rule_object_t *rule_object;

        ret = idmef_path_new(&object, "alert.%s", object_name);
        if ( ret < 0 ) {
                prelude_perror(ret, "%s:%d: could not create 'alert.%s' path", filename, line, object_name);
                return -1;
        }

        if ( idmef_path_is_ambiguous(object) ) {
                prelude_log(PRELUDE_LOG_WARN, "%s:%d: Missing index in path '%s'.\n", filename, line, object_name);
                idmef_path_destroy(object);
                return -1;
        }

        rule_object = malloc(sizeof(*rule_object));
        if ( ! rule_object ) {
                prelude_log(PRELUDE_LOG_ERR, "memory exhausted.\n");
                idmef_path_destroy(object);
                return -1;
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
