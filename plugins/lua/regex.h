/*****
*
* Copyright (C) 2008 PreludeIDS Technologies. All Rights Reserved.
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

int match_idmef_path(lua_State *lstate, idmef_message_t *idmef,
                     const char *path, const char *regex,
                     prelude_string_t *outstr, unsigned int *idx,
                     prelude_bool_t flat, prelude_bool_t has_top_table);

int retrieve_idmef_path(lua_State *lstate, idmef_message_t *idmef,
                        const char *path, unsigned int *idx,
                        prelude_bool_t flat, prelude_bool_t multipath);
