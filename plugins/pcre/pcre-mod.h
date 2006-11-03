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
typedef struct pcre_plugin pcre_plugin_t;
typedef struct pcre_context pcre_context_t;


#include "value-container.h"


/*
 * we can store up to 64 reference value in a rule
 * it should be large enough
 */
#define MAX_REFERENCE_PER_RULE 64

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

        prelude_list_t rule_list;
        prelude_list_t regex_list;
        prelude_list_t operation_list;
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


typedef struct {
        idmef_message_t *idmef;
} pcre_state_t;


struct pcre_operation {
        prelude_list_t list;
        void *extra;
        void (*extra_destroy)(void *extra);
        int (*op)(pcre_plugin_t *plugin, pcre_rule_t *rule,
                  idmef_message_t *input, capture_string_t *capture, void *extra, prelude_list_t *context_result);
};


typedef struct pcre_operation pcre_operation_t;


prelude_list_t *pcre_plugin_get_context_list(pcre_plugin_t *plugin);

int pcre_operation_execute(pcre_plugin_t *plugin, pcre_rule_t *rule,
                           prelude_list_t *operation_list, idmef_message_t *input, capture_string_t *capture);
