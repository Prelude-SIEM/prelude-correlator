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

#include "capture-string.h"

typedef struct rule_object_list rule_object_list_t;

int rule_object_add(rule_object_list_t *olist,
                    const char *filename, int line,
                    const char *object_name, const char *value);

int rule_object_build_message(pcre_rule_t *rule,
                              rule_object_list_t *olist, idmef_message_t **message,
                              idmef_message_t *idmef_input, capture_string_t *capture);

rule_object_list_t *rule_object_list_new(void);

prelude_bool_t rule_object_list_is_empty(rule_object_list_t *olist);

void rule_object_list_destroy(rule_object_list_t *olist);

