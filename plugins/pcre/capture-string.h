/*****
*
* Copyright (C) 2005 PreludeIDS Technologies. All Rights Reserved.
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

#ifndef _CAPTURE_STRING_H
#define _CAPTURE_STRING_H

typedef struct capture_string capture_string_t;

int capture_string_add_string(capture_string_t *capture, const char *string);

int capture_string_new(capture_string_t *parent, capture_string_t **new);

void *capture_string_get_element(capture_string_t *root, unsigned int index);

prelude_bool_t capture_string_is_element_string(capture_string_t *root, unsigned int index);

void capture_string_destroy(capture_string_t *root);

unsigned int capture_string_get_index(capture_string_t *root);

#endif
