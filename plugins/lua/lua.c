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
#include <dirent.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include <libprelude/prelude-timer.h>
#include "prelude-correlator.h"


#include "regex.h"
#include "lua-timer.h"
#include "lua-idmef.h"
#include "lua-idmef-value.h"


int lua_LTX_prelude_plugin_version(void);
int lua_LTX_correlation_plugin_init(prelude_plugin_entry_t *pe, void *data);


typedef struct lua_plugin {
        lua_State *lstate;
} lua_plugin_t;


static prelude_correlator_plugin_t lua_plugin;


static int timeval_subtract (struct timeval *result, struct timeval *x, struct timeval *y)
     {
       /* Perform the carry for the later subtraction by updating y. */
       if (x->tv_usec < y->tv_usec) {
         int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
         y->tv_usec -= 1000000 * nsec;
         y->tv_sec += nsec;
       }
       if (x->tv_usec - y->tv_usec > 1000000) {
         int nsec = (x->tv_usec - y->tv_usec) / 1000000;
         y->tv_usec += 1000000 * nsec;
         y->tv_sec -= nsec;
       }

       /* Compute the time remaining to wait.
          tv_usec is certainly positive. */
       result->tv_sec = x->tv_sec - y->tv_sec;
       result->tv_usec = x->tv_usec - y->tv_usec;

       /* Return 1 if result is negative. */
       return x->tv_sec < y->tv_sec;
     }

static void lua_run(prelude_plugin_instance_t *pi, idmef_message_t *idmef)
{
        int ret;
        struct timeval te, ts, result;
        lua_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(pi);

        if ( idmef_message_get_type(idmef) != IDMEF_MESSAGE_TYPE_ALERT )
                return;

        gettimeofday(&ts, NULL);

        lua_getfield(plugin->lstate, LUA_GLOBALSINDEX, "__main__");

        pushIDMEF(plugin->lstate, idmef_message_ref(idmef));
        ret = lua_pcall(plugin->lstate, 1, 0, 0);

        gettimeofday(&te, NULL);

        timeval_subtract(&result, &te, &ts);
        printf("RAN LUA CODE: %f sec\n", result.tv_sec + result.tv_usec*1e-6);

        if ( ret != 0 )
                prelude_log(PRELUDE_LOG_ERR, "LUA error: %s.\n", lua_tostring(plugin->lstate, -1));

        lua_gc(plugin->lstate, LUA_GCCOLLECT, 0);
}


static int file_read(const char *filename, prelude_string_t *out)
{
        FILE *fd;
        char buf[8192];

        fd = fopen(filename, "r");
        if ( ! fd ) {
                prelude_log(PRELUDE_LOG_ERR, "could not open '%s' for reading: %s.\n", filename, strerror(errno));
                return -1;
        }

        while ( fgets(buf, sizeof(buf), fd) ) {
                prelude_string_cat(out, buf);
        }

        fclose(fd);
        return 0;
}


static int set_lua_ruleset(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        int ret;
        DIR *dir;
        struct dirent *dh;
        char fname[PATH_MAX];
        prelude_string_t *str;
        lua_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(context);

        ret = prelude_string_new(&str);
        if ( ret < 0 )
                return ret;

        dir = opendir(optarg);
        if ( ! dir ) {
                prelude_log(PRELUDE_LOG_ERR, "could not open '%s': %s.\n", optarg, strerror(errno));
                return -1;
        }

        prelude_string_cat(str, "function __main__(INPUT)\n");

        while ( (dh = readdir(dir)) ) {
                if ( ! strstr(dh->d_name, ".lua") )
                        continue;

                snprintf(fname, sizeof(fname), "%s/%s", optarg, dh->d_name);
                file_read(fname, str);
        }

        closedir(dir);
        prelude_string_cat(str, "end\n");

        ret = luaL_dostring(plugin->lstate, prelude_string_get_string(str));
        prelude_string_destroy(str);

        if ( ret != 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "LUA error: %s.\n", lua_tostring(plugin->lstate, -1));
                return -1;
        }

        return 0;
}



static int lua_activate(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        int ret;
        lua_plugin_t *new;

        new = calloc(1, sizeof(*new));
        if ( ! new )
                return prelude_error_from_errno(errno);

        new->lstate = lua_open();
        if ( ! new->lstate ) {
                prelude_log(PRELUDE_LOG_ERR, "error initializing LUA state.\n");
                free(new);
                return -1;
        }

        luaL_openlibs(new->lstate);

        ret = IDMEFValue_register(new->lstate);
        ret = IDMEF_register(new->lstate);
        ret = Timer_register(new->lstate);

        ret = luaL_dofile(new->lstate, LUA_DATADIR "/lib.lua");
        if ( ret != 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "LUA error: %s.\n", lua_tostring(new->lstate, -1));
                lua_close(new->lstate);
                free(new);
                return -1;
        }

        prelude_plugin_instance_set_plugin_data(context, new);

        return 0;
}




static void lua_destroy(prelude_plugin_instance_t *pi, prelude_string_t *err)
{
        lua_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(pi);

        //lua_collectgc(plugin->lstate);
        lua_close(plugin->lstate);
        free(plugin);
}



int lua_LTX_correlation_plugin_init(prelude_plugin_entry_t *pe, void *root_optlist)
{
        int ret;
        prelude_option_t *opt, *popt;
        int hook = PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG;

        ret = prelude_option_add(root_optlist, &opt, hook, 0, "lua", "LUA plugin option",
                                 PRELUDE_OPTION_ARGUMENT_OPTIONAL, lua_activate, NULL);
        if ( ret < 0 )
                return ret;

        prelude_plugin_set_activation_option(pe, opt, NULL);

        ret = prelude_option_add(opt, NULL, hook, 'r', "ruleset", "Ruleset to use",
                                 PRELUDE_OPTION_ARGUMENT_REQUIRED, set_lua_ruleset, NULL);
        if ( ret < 0 )
                return ret;

        lua_plugin.run = lua_run;
        prelude_plugin_set_name(&lua_plugin, "lua");
        prelude_plugin_set_destroy_func(&lua_plugin, lua_destroy);
        prelude_plugin_entry_set_plugin(pe, (void *) &lua_plugin);

        //correlation_plugin_set_signal_func(&lua_plugin, lua_signal);
        //correlation_plugin_register_signal(&lua_plugin, SIGQUIT);

        return 0;
}



int lua_LTX_prelude_plugin_version(void)
{
        return PRELUDE_PLUGIN_API_VERSION;
}
