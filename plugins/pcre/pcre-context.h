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

#include <pcre.h>

typedef enum {
        PCRE_CONTEXT_SETTING_FLAGS_OVERWRITE     = 0x01,
        PCRE_CONTEXT_SETTING_FLAGS_QUEUE         = 0x02,
        PCRE_CONTEXT_SETTING_FLAGS_ALERT_ON_EXPIRE  = 0x04,
        PCRE_CONTEXT_SETTING_FLAGS_ALERT_ON_DESTROY = 0x08
} pcre_context_setting_flags_t;


typedef struct {        
        int timeout;
        prelude_bool_t need_destroy;
        
        value_container_t *vcont;
        pcre_context_setting_flags_t flags;
        
        unsigned int correlation_window;
        unsigned int correlation_threshold;
} pcre_context_setting_t;



typedef struct {
        PRELUDE_LINKED_OBJECT;
        pcre_context_t *ctx;
} pcre_context_container_t;


typedef enum {
        PCRE_CONTEXT_TYPE_UNKNOWN = 0,
        PCRE_CONTEXT_TYPE_FLOAT   = 1,
        PCRE_CONTEXT_TYPE_STRING  = 2,
        PCRE_CONTEXT_TYPE_IDMEF   = 3
} pcre_context_type_t;


int pcre_context_search_regex(prelude_list_t *outlist, pcre_plugin_t *plugin, const pcre *regex);

pcre_context_t *pcre_context_search(pcre_plugin_t *plugin, const char *name);

int pcre_context_new(pcre_context_t **out, pcre_plugin_t *plugin,
                     const char *name, pcre_context_setting_t *setting);

void pcre_context_destroy(pcre_context_t *ctx);

const char *pcre_context_get_name(pcre_context_t *ctx);

prelude_timer_t *pcre_context_get_timer(pcre_context_t *ctx);

void pcre_context_set_threshold(pcre_context_t *ctx, unsigned int threshold);

unsigned int pcre_context_get_threshold(pcre_context_t *ctx);

pcre_context_setting_t *pcre_context_get_setting(pcre_context_t *ctx);

int pcre_context_check_correlation(pcre_context_t *ctx);

void pcre_context_set_value_idmef(pcre_context_t *ctx, idmef_message_t *idmef);

void pcre_context_set_value_string(pcre_context_t *ctx, const char *str);

void pcre_context_set_value_float(pcre_context_t *ctx, float val);

void pcre_context_setting_destroy(pcre_context_setting_t *settings);

void pcre_context_reset_timer(pcre_context_t *ctx);

idmef_message_t *pcre_context_get_value_idmef(pcre_context_t *ctx);

float pcre_context_get_value_float(pcre_context_t *ctx);

const char *pcre_context_get_value_string(pcre_context_t *ctx);

pcre_context_type_t pcre_context_get_type(pcre_context_t *ctx);

int pcre_context_get_value_as_string(pcre_context_t *ctx, prelude_string_t *out);

int pcre_context_set_value_from_string(pcre_plugin_t *plugin, pcre_context_t *ctx, const char *str);

int pcre_context_save(prelude_plugin_instance_t *pi, pcre_plugin_t *plugin);

unsigned int pcre_context_restore(prelude_plugin_instance_t *plugin);

