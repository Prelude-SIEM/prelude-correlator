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

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include <libprelude/prelude.h>
#include <libprelude/idmef-message-print.h>

#include "prelude-correlator.h"
#include "lua-idmef-value.h"


#define IDMEF_VALUE_CLASS "IDMEFValue"


static idmef_value_t *toIDMEFValue(lua_State *lstate, int index)
{
        idmef_value_t **value;

        value = lua_touserdata(lstate, index);
        if ( ! value )
                luaL_typerror(lstate, index, IDMEF_VALUE_CLASS);

        return *value;
}


idmef_value_t *checkIDMEFValue(lua_State *lstate, int index)
{
        idmef_value_t **ptr, *value;

        luaL_checktype(lstate, index, LUA_TUSERDATA);

        ptr = luaL_checkudata(lstate, index, IDMEF_VALUE_CLASS);
        if ( ! ptr )
                luaL_typerror(lstate, index, IDMEF_VALUE_CLASS);

        value = *ptr;
        if ( ! value )
                luaL_error(lstate, "IDMEFValue is NULL!\n");

        return value;
}


idmef_value_t *pushIDMEFValue(lua_State *lstate, idmef_value_t *value)
{
        idmef_value_t **ptr;

        ptr = lua_newuserdata(lstate, sizeof(*ptr));
        *ptr = value;

        luaL_getmetatable(lstate, IDMEF_VALUE_CLASS);
        lua_setmetatable(lstate, -2);

        return *ptr;
}

static const luaL_reg IDMEFValue_methods[] = {
        { 0, 0                 }
};


static int IDMEFValue_gc(lua_State *lstate)
{
        idmef_value_t *value;

        value = toIDMEFValue(lstate, 1);
        if ( value )
                idmef_value_destroy(value);

        prelude_log_debug(1, "[gc] IDMEFValue at %p\n", value);
        return 0;
}


static int IDMEFValue_tostring(lua_State *lstate)
{
        int ret;
        prelude_string_t *str;
        idmef_value_t *value;

        value = checkIDMEFValue(lstate, 1);

        ret = prelude_string_new(&str);
        if ( ret < 0 )
                return ret;

        ret = idmef_value_to_string(value, str);
        if ( ret < 0 ) {
                prelude_string_destroy(str);
                return ret;
        }

        lua_pushlstring(lstate, prelude_string_get_string(str), prelude_string_get_len(str));
        prelude_string_destroy(str);

        return 1;
}


static const luaL_reg IDMEFValue_meta[] = {
        { "__gc"     , IDMEFValue_gc       },
        {"__tostring", IDMEFValue_tostring },
        { 0, 0                             }
};



int IDMEFValue_register(lua_State *lstate)
{
        //luaL_openlib(lstate, IDMEF_VALUE_CLASS, IDMEFValue_methods, 0);
        luaL_newmetatable(lstate, IDMEF_VALUE_CLASS);

        luaL_openlib(lstate, 0, IDMEFValue_meta, 0);

        lua_pushliteral(lstate, "__index");
        lua_pushvalue(lstate, -3);
        lua_rawset(lstate, -3);
        lua_pushliteral(lstate, "__metatable");
        lua_pushvalue(lstate, -3);
        lua_rawset(lstate, -3);
        lua_pop(lstate, 1);

        return 1;
}
