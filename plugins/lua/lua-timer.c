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
#include "lua-timer.h"


#define TIMER_CLASS "Timer"


struct lua_timer {
        prelude_bool_t is_active;
        prelude_timer_t timer;
        char *data;
        lua_State *lstate;
};



static void timer_cb(void *data)
{
        int ret;
        lua_timer_t *timer = data;

        lua_getglobal(timer->lstate, "_del_context_");
        lua_pushstring(timer->lstate, timer->data);

        ret = lua_pcall(timer->lstate, 1, 0, 0);
        if ( ret != 0 )
                prelude_log(PRELUDE_LOG_ERR, "LUA error: %s.\n", lua_tostring(timer->lstate, -1));


        //lua_gc(timer->lstate, LUA_GCCOLLECT, 0);

        timer->is_active = FALSE;
        prelude_timer_destroy(&timer->timer);
}



static lua_timer_t *toTimer(lua_State *lstate, int index)
{
        lua_timer_t *timer;

        timer = lua_touserdata(lstate, index);
        if ( ! timer )
                luaL_typerror(lstate, index, TIMER_CLASS);

        return timer;
}


static lua_timer_t *checkTimer(lua_State *lstate, int index)
{
        lua_timer_t *timer;

        luaL_checktype(lstate, index, LUA_TUSERDATA);

        timer = luaL_checkudata(lstate, index, TIMER_CLASS);
        if ( ! timer )
                luaL_typerror(lstate, index, TIMER_CLASS);

        return timer;
}


lua_timer_t *pushTimer(lua_State *lstate, const char *cname)
{
        char *dup;
        lua_timer_t *timer;

        dup = strdup(cname);
        if ( ! dup )
                return NULL;

        timer = lua_newuserdata(lstate, sizeof(*timer));
        timer->is_active = FALSE;
        timer->data = dup;
        timer->lstate = lstate;

        luaL_getmetatable(lstate, TIMER_CLASS);
        lua_setmetatable(lstate, -2);

        return timer;
}


static int Timer_new(lua_State *lstate)
{
        int ret;
        lua_timer_t *timer;

        ret = lua_gettop(lstate);
        if ( ret != 1 ) {
                prelude_log(PRELUDE_LOG_ERR, "timer_start(): require 1 arguments, got %d.\n", ret);
                return -1;
        }

        if ( ! lua_isstring(lstate, 1) ) {
                prelude_log(PRELUDE_LOG_ERR, "timer_init(): First argument should be 'string'.\n");
                return -1;
        }

        timer = pushTimer(lstate, lua_tostring(lstate, 1));
        return 1;
}


static int Timer_start(lua_State *lstate)
{
        int ret;
        lua_timer_t *timer;

        ret = lua_gettop(lstate);
        if ( ret != 2 ) {
                prelude_log(PRELUDE_LOG_ERR, "timer_start(): require 2 arguments, got %d.\n", ret);
                return -1;
        }

        timer = checkTimer(lstate, 1);
        if ( ! timer ) {
                prelude_log(PRELUDE_LOG_ERR, "timer_init(): First argument should be a 'Timer'.\n");
                return -1;
        }

        if ( ! lua_isnumber(lstate, 2) ) {
                prelude_log(PRELUDE_LOG_ERR, "timer_init(): First argument should be a 'number'.\n");
                return -1;
        }

        timer->is_active = TRUE;
        prelude_timer_set_data(&timer->timer, timer);
        prelude_timer_set_expire(&timer->timer, lua_tonumber(lstate, 2));
        prelude_timer_set_callback(&timer->timer, timer_cb);
        prelude_timer_init(&timer->timer);

        return 0;
}


static int Timer_reset(lua_State *lstate)
{
        int ret;
        lua_timer_t *timer;

        ret = lua_gettop(lstate);
        if ( ret != 2 ) {
                prelude_log(PRELUDE_LOG_ERR, "timer_reset(): require 2 arguments, got %d.\n", ret);
                return -1;
        }

        timer = checkTimer(lstate, 1);
        if ( ! timer ) {
                prelude_log(PRELUDE_LOG_ERR, "timer_reset(): First argument should be 'Timer'.\n");
                return -1;
        }

        if ( ! lua_isnumber(lstate, 2) ) {
                prelude_log(PRELUDE_LOG_ERR, "timer_reset(): Second argument should be a 'number'.\n");
                return -1;
        }

        timer->is_active = TRUE;
        prelude_timer_set_expire(&timer->timer, lua_tonumber(lstate, 2));
        prelude_timer_reset(&timer->timer);

        return 0;
}


static int Timer_stop(lua_State *lstate)
{
        int ret;
        lua_timer_t *timer;

        ret = lua_gettop(lstate);
        if ( ret != 1 ) {
                prelude_log(PRELUDE_LOG_ERR, "timer_reset(): require 1 arguments, got %d.\n", ret);
                return -1;
        }

        timer = checkTimer(lstate, 1);
        if ( ! timer ) {
                prelude_log(PRELUDE_LOG_ERR, "timer_reset(): First argument should be 'Timer'.\n");
                return -1;
        }

        timer->is_active = FALSE;
        prelude_timer_destroy(&timer->timer);

        return 0;
}


static const luaL_reg Timer_methods[] = {
        { "new", Timer_new     },
        { "start", Timer_start },
        { "stop", Timer_stop   },
        { "reset", Timer_reset },
        { 0, 0                 }
};


static int Timer_gc(lua_State *lstate)
{
        lua_timer_t *timer;

        timer = toTimer(lstate, 1);
        if ( timer && timer->is_active )
                prelude_timer_destroy(&timer->timer);

        free(timer->data);

        prelude_log_debug(1, "[gc] TIMER at %p\n", timer);
        return 0;
}


static const luaL_reg Timer_meta[] = {
        { "__gc"     , Timer_gc       },
        { 0, 0                        }
};



int Timer_register(lua_State *lstate)
{
        luaL_openlib(lstate, TIMER_CLASS, Timer_methods, 0);
        luaL_newmetatable(lstate, TIMER_CLASS);

        luaL_openlib(lstate, 0, Timer_meta, 0);

        lua_pushliteral(lstate, "__index");
        lua_pushvalue(lstate, -3);
        lua_rawset(lstate, -3);
        lua_pushliteral(lstate, "__metatable");
        lua_pushvalue(lstate, -3);
        lua_rawset(lstate, -3);
        lua_pop(lstate, 1);

        return 1;
}
