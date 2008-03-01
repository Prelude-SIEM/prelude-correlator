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
#include "lua-idmef.h"
#include "lua-idmef-value.h"
#include "regex.h"

#define IDMEF_CLASS "IDMEF"


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

        if ( mcb->value ) {
                ret = idmef_value_match(value, mcb->value, IDMEF_CRITERION_OPERATOR_EQUAL);
                if ( ret < 0 )
                        prelude_perror(ret, "comparison failed");
        }

        if ( ret == 0 ) {
                ret = idmef_path_set(mcb->path, mcb->idmef, value);
                if ( ret < 0 )
                        prelude_perror(ret, "could not set output path '%s'", idmef_path_get_name(mcb->path, -1));
        }

        return 0;
}




static int copy_idmef_path_if_needed(idmef_message_t *output, const idmef_path_t *path, idmef_value_t *value)
{
        int ret;
        match_cb_t mcb;

        mcb.path = path;
        mcb.value = NULL;
        mcb.idmef = output;

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
        if ( prelude_error_get_code(ret) == PRELUDE_ERROR_IDMEF_PATH_INDEX_UNDEFINED ) {

                ret = idmef_path_set(path, output, value);
                if ( ret < 0 )
                        prelude_perror(ret, "could not set output path '%s'", idmef_path_get_name(path, -1));

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

        if ( mcb.value )
                idmef_value_destroy(mcb.value);

        return ret;
}



static idmef_message_t *toIDMEF(lua_State *lstate, int index)
{
        idmef_message_t **idmef;

        idmef = lua_touserdata(lstate, index);
        if ( ! idmef )
                luaL_typerror(lstate, index, IDMEF_CLASS);

        return *idmef;
}


static idmef_message_t *checkIDMEF(lua_State *lstate, int index)
{
        idmef_message_t **ptr, *idmef;

        luaL_checktype(lstate, index, LUA_TUSERDATA);

        ptr = luaL_checkudata(lstate, index, IDMEF_CLASS);
        if ( ! ptr )
                luaL_typerror(lstate, index, IDMEF_CLASS);

        idmef = *ptr;
        if ( ! idmef )
                luaL_error(lstate, "IDMEF message is NULL!\n");

        return idmef;
}


idmef_message_t *pushIDMEF(lua_State *lstate, idmef_message_t *idmef)
{
        idmef_message_t **ptr;

        ptr = lua_newuserdata(lstate, sizeof(*ptr));
        *ptr = idmef;

        luaL_getmetatable(lstate, IDMEF_CLASS);
        lua_setmetatable(lstate, -2);

        return *ptr;
}


static int IDMEF_new(lua_State *lstate)
{
        int ret;
        idmef_message_t *idmef;

        ret = idmef_message_new(&idmef);
        if ( ret < 0 )
                return ret;

        pushIDMEF(lstate, idmef);

        return 1;
}


static int IDMEF_alert(lua_State *lstate)
{
        int ret;
        idmef_message_t *idmef;

        ret = lua_gettop(lstate);
        if ( ret != 1 ) {
                prelude_log(PRELUDE_LOG_ERR, "Alert(): require 1 arguments, got %d.\n", ret);
                return -1;
        }

        idmef = checkIDMEF(lstate, 1);
        correlation_alert_emit(idmef);

        return 0;
}


static int IDMEF_set(lua_State *lstate)
{
        int ret;
        const char *paths;
        idmef_path_t *path;
        idmef_value_t *value;
        idmef_message_t *idmef;
        prelude_bool_t nofree = FALSE;

        ret = lua_gettop(lstate);
        if ( ret != 3 ) {
                prelude_log(PRELUDE_LOG_ERR, "Set(): require 3 arguments, got %d.\n", ret);
                return -1;
        }

        idmef = checkIDMEF(lstate, 1);
        if ( ! idmef ) {
                prelude_log(PRELUDE_LOG_ERR, "Set(): First argument should be 'IDMEF'.\n");
                return -1;
        }

        if ( ! lua_isstring(lstate, 2) ) {
                prelude_log(PRELUDE_LOG_ERR, "Set(): Second argument should be 'string'.\n");
                return -1;
        }

        paths = lua_tostring(lstate, 2);

        ret = idmef_path_new_fast(&path, paths);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "could not create path '%s': %s.\n", paths, prelude_strerror(ret));
                return -1;
        }

        if ( lua_isstring(lstate, 3) ) {
                prelude_string_t *str;
                ret = prelude_string_new_dup(&str, lua_tostring(lstate, 3));
                ret = idmef_value_new_string(&value, str);
        }

        else if ( lua_isnumber(lstate, 3) )
                ret = idmef_value_new_double(&value, lua_tonumber(lstate, 3));

        else if ( (value = checkIDMEFValue(lstate, 3)) )
                nofree = TRUE;

        else {
                idmef_path_destroy(path);
                prelude_log(PRELUDE_LOG_ERR, "Unexpected third argument for Set(%s).\n", paths);
                return -1;
        }

        ret = copy_idmef_path_if_needed(idmef, path, value);
        idmef_path_destroy(path);

        if ( ! nofree )
                idmef_value_destroy(value);

        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "error setting path '%s': %s.\n", paths, prelude_strerror(ret));
                return -1;
        }

        return 0;
}


static int IDMEF_getraw(lua_State *lstate)
{
        int ret;
        idmef_path_t *path;
        idmef_value_t *value;
        idmef_message_t *idmef;
        const char *path_str;

        ret = lua_gettop(lstate);
        if ( ret != 2 ) {
                prelude_log(PRELUDE_LOG_ERR, "getraw(): require 2 arguments, got %d.\n", ret);
                return -1;
        }

        idmef = checkIDMEF(lstate, 1);
        if ( ! idmef ) {
                prelude_log(PRELUDE_LOG_ERR, "getraw(): First argument should be 'IDMEF'.\n");
                return -1;
        }

        if ( ! lua_isstring(lstate, 2) ) {
                prelude_log(PRELUDE_LOG_ERR, "getraw(): Second argument should be 'string'.\n");
                return -1;
        }

        path_str = lua_tostring(lstate, 2);

        ret = idmef_path_new_fast(&path, path_str);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "getraw(%s): %s.\n", path_str, prelude_strerror(ret));
                return -1;
        }

        ret = idmef_path_get(path, idmef, &value);
        idmef_path_destroy(path);

        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "getraw(%s): retrieval failed: %s.\n", path_str, prelude_strerror(ret));
                return -1;
        }

        if ( ret == 0 )
                return 0;

        pushIDMEFValue(lstate, value);

        return 1;
}


static int IDMEF_get(lua_State *lstate)
{
        int ret, i, top;
        unsigned int idx = 1;
        idmef_message_t *idmef;
        prelude_bool_t flat = TRUE, multipath = FALSE;

        ret = lua_gettop(lstate);
        if ( ret < 2 ) {
                prelude_log(PRELUDE_LOG_ERR, "get(): require 2 arguments minimum, got %d.\n", ret);
                return -1;
        }

        idmef = checkIDMEF(lstate, 1);
        if ( ! idmef ) {
                prelude_log(PRELUDE_LOG_ERR, "get(): First argument should be 'IDMEF'.\n");
                return -1;
        }

        top = lua_gettop(lstate);

        if ( lua_isboolean(lstate, top) ) {
                flat = lua_toboolean(lstate, top);
                top--;
        }

        multipath = (top - 3) > 0 ? TRUE : FALSE;
        if ( multipath )
                lua_newtable(lstate);

        for ( i = 2; i <= top; i++ ) {

                ret = retrieve_idmef_path(lstate, idmef, lua_tostring(lstate, i), &idx, flat, multipath);
                if ( ret < 0 ) {
                        ret = 0;
                        break;
                }

                ret = 1;
        }

        return ret;
}



static int IDMEF_match(lua_State *lstate)
{
        int ret, i, top;
        prelude_string_t *str;
        unsigned int idx = 1;
        idmef_message_t *idmef;
        const char *path, *regexp;
        prelude_bool_t flat = TRUE, multipath = FALSE;

        ret = lua_gettop(lstate);
        if ( ret < 3 ) {
                prelude_log(PRELUDE_LOG_ERR, "match(): require 3 arguments minimum, got %d.\n", ret);
                return -1;
        }

        idmef = checkIDMEF(lstate, 1);
        if ( ! idmef ) {
                prelude_log(PRELUDE_LOG_ERR, "match(): First argument should be 'IDMEF'.\n");
                return -1;
        }

        ret = prelude_string_new(&str);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "Match(): error creating string object.\n");
                return -1;
        }

        top = lua_gettop(lstate);

        if ( lua_isboolean(lstate, top) ) {
                flat = lua_toboolean(lstate, top);
                top--;
        }

        multipath = (top - 3) > 0 ? TRUE : FALSE;
        if ( multipath )
                lua_newtable(lstate);

        for ( i = 2; i <= top; i += 2 ) {
                path = lua_tostring(lstate, i);
                regexp = lua_tostring(lstate, i + 1);

                ret = match_idmef_path(lstate, idmef, path, regexp, str, &idx, flat, multipath);
                if ( ret < 0 ) {
                        ret = 0;
                        break;
                }

                prelude_string_clear(str);
                ret = 1;
        }

        prelude_string_destroy(str);
        return ret;
}




static const luaL_reg IDMEF_methods[] = {
        { "new", IDMEF_new     },
        { "set", IDMEF_set     },
        { "get", IDMEF_get     },
        { "getraw", IDMEF_getraw },
        { "match", IDMEF_match },
        { "alert", IDMEF_alert },
        { 0, 0                 }
};


static int IDMEF_gc(lua_State *lstate)
{
        idmef_message_t *idmef;

        idmef = toIDMEF(lstate, 1);
        if ( idmef )
                idmef_message_destroy(idmef);

        prelude_log_debug(1, "[gc] IDMEF at %p\n", idmef);
        return 0;
}


static int IDMEF_tostring(lua_State *lstate)
{
        int ret;
        prelude_io_t *io;
        idmef_message_t *idmef;

        idmef = lua_touserdata(lstate, 1);

        ret = prelude_io_new(&io);
        if ( ret < 0 )
                return ret;

        prelude_io_set_buffer_io(io);
        idmef_message_print(idmef, io);

        lua_pushlstring(lstate, prelude_io_get_fdptr(io), prelude_io_pending(io));

        return 1;
}


static const luaL_reg IDMEF_meta[] = {
        { "__gc"     , IDMEF_gc       },
        {"__tostring", IDMEF_tostring },
        { 0, 0                        }
};



int IDMEF_register(lua_State *lstate)
{
        luaL_openlib(lstate, IDMEF_CLASS, IDMEF_methods, 0);
        luaL_newmetatable(lstate, IDMEF_CLASS);

        luaL_openlib(lstate, 0, IDMEF_meta, 0);

        lua_pushliteral(lstate, "__index");
        lua_pushvalue(lstate, -3);
        lua_rawset(lstate, -3);
        lua_pushliteral(lstate, "__metatable");
        lua_pushvalue(lstate, -3);
        lua_rawset(lstate, -3);
        lua_pop(lstate, 1);

        return 1;
}
