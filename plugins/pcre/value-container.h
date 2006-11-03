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

#ifndef VALUE_CONTAINER_H
#define VALUE_CONTAINER_H

#include "capture-string.h"

typedef struct value_container value_container_t;

int value_container_new(value_container_t **vcont, const char *str);

void value_container_destroy(value_container_t *vcont);

void value_container_reset(value_container_t *vcont);

void *value_container_get_data(value_container_t *vcont);

void value_container_set_data(value_container_t *vcont, void *data);

int value_container_resolve_listed(prelude_list_t *outlist, value_container_t *vcont,
                                   pcre_plugin_t *plugin, const pcre_rule_t *rule, capture_string_t *capture);

prelude_string_t *value_container_resolve(value_container_t *vcont,
                                          pcre_plugin_t *plugin, const pcre_rule_t *rule, capture_string_t *capture);

#endif
