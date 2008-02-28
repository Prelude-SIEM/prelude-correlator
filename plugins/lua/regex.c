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
#include <ctype.h>
#include <sys/types.h>
#include <pcre.h>

#include <lua.h>
#include <libprelude/prelude.h>


#define MAX_REFERENCE_PER_RULE 64


#ifndef MIN
# define MIN(x, y) (((x) < (y)) ? (x) : (y))
#endif

#ifndef MAX
# define MAX(x, y) (((x) > (y)) ? (x) : (y))
#endif


struct exec_pcre_cb_data {
        unsigned int *index;
        lua_State *lstate;
        pcre *regex;
        const char *regex_string;
        prelude_string_t *subject;
        int ovector[MAX_REFERENCE_PER_RULE * 3];
};



/*
 * In a match where some of the capture are not required, pcre_exec will
 * not always return the _full_ number of captured substring. This function
 * make sure that all not captured substring are set to -1, and then return
 * the total of substring, including the one that were not captured.
 */
static int do_pcre_exec(struct exec_pcre_cb_data *item, int *real_ret)
{
        int cnt = 0, i;
        size_t osize = sizeof(item->ovector) / sizeof(*item->ovector);

        *real_ret = pcre_exec(item->regex, NULL,
                              prelude_string_get_string(item->subject),
                              prelude_string_get_len(item->subject), 0, 0,
                              item->ovector, osize);

        prelude_log_debug(9, "[%d]: '%s' against '%s'.\n", *real_ret, item->regex_string,
                          prelude_string_get_string(item->subject));

        if ( *real_ret <= 0 )
                return *real_ret;

        pcre_fullinfo(item->regex, NULL, PCRE_INFO_CAPTURECOUNT, &cnt);
        if ( cnt == 0 )
                return *real_ret;

        for ( i = (*real_ret * 2); (i + 2) < (MIN(osize, cnt + 1) * 2); i += 2 )
                item->ovector[i] = item->ovector[i + 1] = -1;

        return cnt + 1;
}



static int exec_pcre_cb(void *ptr)
{
        char buf[1024];
        int ret, real_ret, i;
        struct exec_pcre_cb_data *data = ptr;

        /*
         * arg:
         * - subject
         */

        ret = do_pcre_exec(data, &real_ret);
        if ( ret < 0 )
                return ret;

        for ( i = 1; i < ret; i++ ) {
                pcre_copy_substring(prelude_string_get_string(data->subject),
                                    data->ovector, real_ret, i, buf, sizeof(buf));

                lua_pushstring(data->lstate, buf);
                lua_rawseti(data->lstate, -2, (*data->index)++);
        }

        return i;
}



static int maybe_listed_value_cb(idmef_value_t *value, void *extra)
{
        int ret;
        struct exec_pcre_cb_data *data = extra;

        if ( idmef_value_is_list(value) ) {
                unsigned int idx = 1, *prev = data->index;

                lua_pushnumber(data->lstate, (*data->index)++);
                lua_newtable(data->lstate);

                data->index = &idx;
                ret = idmef_value_iterate(value, maybe_listed_value_cb, data);
                data->index = prev;

                lua_settable(data->lstate, -3);
        } else {
                prelude_string_clear(data->subject);

                ret = idmef_value_to_string(value, data->subject);
                if ( ret < 0 )
                        return ret;

                ret = exec_pcre_cb(extra);
        }


        return ret;
}



int match_idmef_path(lua_State *lstate, idmef_message_t *idmef,
                     const char *path, const char *regex, prelude_string_t *outstr, unsigned int *idx)
{
        int ret;
        int err_offset;
        const char *err_ptr;
        idmef_value_t *value;
        idmef_path_t *ipath;
        struct exec_pcre_cb_data data;

        ret = idmef_path_new_fast(&ipath, path);
        if ( ret < 0 )
                return ret;

        ret = idmef_path_get(ipath, idmef, &value);
        idmef_path_destroy(ipath);

        if ( ret < 0 )
                return ret;

        data.regex = pcre_compile(regex, 0, &err_ptr, &err_offset, NULL);
        if ( ! data.regex ) {
                if ( ret > 0 )
                        idmef_value_destroy(value);

                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "unable to compile regex: %s", err_ptr);
        }

        data.index = idx;
        data.lstate = lstate;
        data.subject = outstr;
        data.regex_string = regex;

        if ( ret == 0 ) {
                prelude_string_set_constant(outstr, "");
                ret = exec_pcre_cb(&data);
                pcre_free(data.regex);
                return ret;
        }

        ret = maybe_listed_value_cb(value, &data);
        idmef_value_destroy(value);
        pcre_free(data.regex);

        return ret;
}


