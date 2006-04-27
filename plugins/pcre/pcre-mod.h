/*****
*
* Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005 PreludeIDS Technologies. All Rights Reserved.
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

typedef struct pcre_rule pcre_rule_t;
#include "value-container.h"


/*
 * we can store up to 64 reference value in a rule
 * it should be large enough
 */
#define MAX_REFERENCE_PER_RULE 64

typedef struct pcre_plugin pcre_plugin_t;
typedef struct pcre_context pcre_context_t;

typedef enum {
        PCRE_RULE_FLAGS_LAST    = 0x01,
        PCRE_RULE_FLAGS_CHAINED = 0x02,
        PCRE_RULE_FLAGS_SILENT  = 0x04,
} pcre_rule_flags_t;


struct pcre_rule {
        /**/
        unsigned int id;
                
        /**/
        uint8_t revision;
        uint8_t refcount;
        uint8_t min_optgoto_match;
        uint8_t min_optregex_match;
        
        /**/
        pcre_rule_flags_t flags;

        
        prelude_list_t create_context_list;
        prelude_list_t destroy_context_list;
        prelude_list_t not_context_list;
        
        value_container_t *required_context;
        value_container_t *optional_context;
                
        prelude_list_t rule_list;
        prelude_list_t regex_list;

        struct rule_object_list *action_object_list;
        struct rule_object_list *pre_action_object_list;
};



typedef struct {
        prelude_list_t list;

        pcre_rule_t *rule;
        prelude_bool_t optional;
} pcre_rule_container_t;



typedef enum {
        PCRE_MATCH_FLAGS_LAST  = 0x01,
        PCRE_MATCH_FLAGS_ALERT = 0x02
} pcre_match_flags_t;



typedef enum {
        PCRE_CONTEXT_SETTING_FLAGS_OVERWRITE     = 0x01,
        PCRE_CONTEXT_SETTING_FLAGS_QUEUE         = 0x02,
        PCRE_CONTEXT_SETTING_FLAGS_ALERT_ON_EXPIRE  = 0x04,
        PCRE_CONTEXT_SETTING_FLAGS_ALERT_ON_DESTROY = 0x08
} pcre_context_setting_flags_t;


typedef struct {
        int timeout;
        pcre_context_setting_flags_t flags;
        
        unsigned int correlation_window;
        unsigned int correlation_threshold;
} pcre_context_setting_t;

#if 0
typedef struct {
        unsigned int window;
        unsigned int threshold;
} correlation_setting_t;
#endif

pcre_context_t *pcre_context_search(pcre_plugin_t *plugin, const char *name);

int pcre_context_new(pcre_context_t **out, pcre_plugin_t *plugin,
                     const char *name, idmef_message_t *idmef, pcre_context_setting_t *setting);

void pcre_context_destroy(pcre_context_t *ctx);

idmef_message_t *pcre_context_get_idmef(pcre_context_t *ctx);

int pcre_context_check_correlation(pcre_context_t *ctx, pcre_context_setting_t *setting);

