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
#include <libprelude/prelude-hash.h>

#include "regex.h"


#define MAX_REFERENCE_PER_RULE 64


#ifndef MIN
# define MIN(x, y) (((x) < (y)) ? (x) : (y))
#endif

#ifndef MAX
# define MAX(x, y) (((x) > (y)) ? (x) : (y))
#endif


typedef struct {
        char *string;
        pcre *regex;
        pcre_extra *extra;
} prepared_pcre_t;


struct exec_pcre_cb_data {
        prepared_pcre_t *pp;
        int (*cb)(idmef_value_t *value, void *data, prelude_bool_t push);
        prelude_bool_t flat, has_top_table;
        unsigned int *index;
        lua_State *lstate;
        prelude_string_t *subject;
        int ovector[MAX_REFERENCE_PER_RULE * 3];
};



static prelude_hash_t *regex_table = NULL;



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

        *real_ret = pcre_exec(item->pp->regex, item->pp->extra,
                              prelude_string_get_string(item->subject),
                              prelude_string_get_len(item->subject), 0, 0,
                              item->ovector, osize);

        prelude_log_debug(9, "[%d]: '%s' against '%s'.\n", *real_ret, item->pp->string,
                          prelude_string_get_string(item->subject));

        if ( *real_ret <= 0 )
                return *real_ret;

        pcre_fullinfo(item->pp->regex, item->pp->extra, PCRE_INFO_CAPTURECOUNT, &cnt);
        if ( cnt == 0 )
                return *real_ret;

        for ( i = (*real_ret * 2); (i + 2) < (MIN(osize, cnt + 1) * 2); i += 2 )
                item->ovector[i] = item->ovector[i + 1] = -1;

        return cnt + 1;
}



static int exec_pcre_cb(idmef_value_t *value, void *ptr, prelude_bool_t push_data)
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

                //if ( push_data ) {
                        lua_pushstring(data->lstate, buf);

                        if ( data->has_top_table )
                                lua_rawseti(data->lstate, -2, (*data->index)++);
                //}
        }

        return i;
}


static void pushIDMEFTime(lua_State *lstate, idmef_time_t *time)
{
        time_t t;
        struct tm *tb;

        t = idmef_time_get_sec(time) + idmef_time_get_gmt_offset(time);

        tb = gmtime(&t);

        lua_newtable(lstate);

        lua_pushstring(lstate, "year");
        lua_pushnumber(lstate, 1900 + tb->tm_year);
        lua_settable(lstate, -3);

        lua_pushstring(lstate, "month");
        lua_pushnumber(lstate, tb->tm_mon + 1);
        lua_settable(lstate, -3);

        lua_pushstring(lstate, "day");
        lua_pushnumber(lstate, tb->tm_mday);
        lua_settable(lstate, -3);

        lua_pushstring(lstate, "yday");
        lua_pushnumber(lstate, tb->tm_yday);
        lua_settable(lstate, -3);

        lua_pushstring(lstate, "wday");
        lua_pushnumber(lstate, tb->tm_wday + 1);
        lua_settable(lstate, -3);

        lua_pushstring(lstate, "hour");
        lua_pushnumber(lstate, tb->tm_hour);
        lua_settable(lstate, -3);

        lua_pushstring(lstate, "min");
        lua_pushnumber(lstate, tb->tm_min);
        lua_settable(lstate, -3);

        lua_pushstring(lstate, "sec");
        lua_pushnumber(lstate, tb->tm_sec);
        lua_settable(lstate, -3);

        lua_pushstring(lstate, "usec");
        lua_pushnumber(lstate, idmef_time_get_usec(time));
        lua_settable(lstate, -3);

        lua_pushstring(lstate, "gmtoff");
        lua_pushnumber(lstate, idmef_time_get_gmt_offset(time));
        lua_settable(lstate, -3);
}


static int retrieve_cb(idmef_value_t *value, void *ptr, prelude_bool_t push_data)
{
        idmef_value_type_id_t type;
        struct exec_pcre_cb_data *data = ptr;
        lua_State *lstate = data->lstate;

        type = idmef_value_get_type(value);
        switch (type) {
                case IDMEF_VALUE_TYPE_STRING: {
                        prelude_string_t *s = idmef_value_get_string(value);
                        lua_pushlstring(lstate, prelude_string_get_string(s), prelude_string_get_len(s));
                        break;
                }

                case IDMEF_VALUE_TYPE_INT8:
                        lua_pushnumber(lstate, idmef_value_get_int8(value));
                        break;

                case IDMEF_VALUE_TYPE_UINT8:
                        lua_pushnumber(lstate, idmef_value_get_uint8(value));
                        break;

                case IDMEF_VALUE_TYPE_INT16:
                        lua_pushnumber(lstate, idmef_value_get_int16(value));
                        break;

                case IDMEF_VALUE_TYPE_UINT16:
                        lua_pushnumber(lstate, idmef_value_get_uint16(value));
                        break;

                case IDMEF_VALUE_TYPE_INT32:
                        lua_pushnumber(lstate, idmef_value_get_int32(value));
                        break;

                case IDMEF_VALUE_TYPE_UINT32:
                        lua_pushnumber(lstate, idmef_value_get_uint32(value));
                        break;

                case IDMEF_VALUE_TYPE_INT64:
                        lua_pushnumber(lstate, idmef_value_get_int64(value));
                        break;

                case IDMEF_VALUE_TYPE_UINT64:
                        lua_pushnumber(lstate, idmef_value_get_uint64(value));
                        break;

                case IDMEF_VALUE_TYPE_FLOAT:
                        lua_pushnumber(lstate, idmef_value_get_float(value));
                        break;

                case IDMEF_VALUE_TYPE_DOUBLE:
                        lua_pushnumber(lstate, idmef_value_get_double(value));
                        break;

                case IDMEF_VALUE_TYPE_TIME:
                        pushIDMEFTime(lstate, idmef_value_get_time(value));
                        break;

                default:
                        return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "could not handle value type '%d'", type);
        }

        if ( data->has_top_table )
                lua_rawseti(lstate, -2, (*data->index)++);

        return 1;
}


static int maybe_listed_value_both_cb(idmef_value_t *value, void *extra)
{
        int ret;
        prelude_bool_t prev_has = FALSE;
        unsigned int *prev = NULL, idx = 1;
        struct exec_pcre_cb_data *data = extra;

        if ( idmef_value_is_list(value) ) {
                if ( ! data->flat ) {
                        if ( data->has_top_table )
                                lua_pushnumber(data->lstate, (*data->index)++);

                        lua_newtable(data->lstate);

                        prev = data->index;
                        data->index = &idx;
                        prev_has = data->has_top_table;
                        data->has_top_table = TRUE;
                }

                ret = idmef_value_iterate(value, maybe_listed_value_both_cb, data);

                if ( ! data->flat ) {
                        data->index = prev;
                        data->has_top_table = prev_has;

                        if ( data->has_top_table )
                                lua_settable(data->lstate, -3);
                }

        } else {
                prelude_string_clear(data->subject);

                ret = idmef_value_to_string(value, data->subject);
                if ( ret < 0 )
                        return ret;

                ret = data->cb(value, extra, TRUE);
                prelude_string_clear(data->subject);
        }

        return ret;
}



int retrieve_idmef_path(lua_State *lstate, idmef_message_t *idmef,
                        const char *path, unsigned int *idx,
                        prelude_bool_t flat, prelude_bool_t multipath)
{
        int ret;
        unsigned int lidx = 1;
        idmef_path_t *ipath;
        idmef_value_t *value;
        prelude_bool_t ambiguous;
        struct exec_pcre_cb_data data;

        ret = idmef_path_new_fast(&ipath, path);
        if ( ret < 0 )
                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "error creating IDMEF path '%s': %s\n", path, prelude_strerror(ret));;

        ret = idmef_path_get(ipath, idmef, &value);
        idmef_path_destroy(ipath);

        if ( ret == 0 ) {
                (*idx)++; /* this index is nil */
                return 0;
        }

        if ( ret < 0 )
                return ret;

        data.cb = retrieve_cb;
        data.index = idx;
        data.lstate = lstate;
        data.flat = flat;
        data.has_top_table = multipath;

        ambiguous = idmef_path_is_ambiguous(ipath);

        if ( flat && multipath && ambiguous ) {
                /*
                 * Multiple path (this function is going to be called
                 * several time), with possibly multiple value, flattened:
                 *
                 * Create a new table holding value for this path, which will
                 * be part of the parent main table.
                 */
                data.index = &lidx;
                lua_pushnumber(lstate, (*idx)++);
                lua_newtable(lstate);
                data.has_top_table = TRUE;
        }

        else if ( flat && ! multipath && ambiguous ) {
                /*
                 * Single path, with possibly multiple value, flattened:
                 * We need a main table to store all the value.
                 */
                lua_newtable(lstate);
                data.has_top_table = TRUE;
        }

        prelude_string_new(&data.subject);
        ret = maybe_listed_value_both_cb(value, &data);

        if ( flat && multipath && ambiguous )
                lua_settable(lstate, -3);

        idmef_value_destroy(value);
        prelude_string_destroy(data.subject);

        return 1;
}


static int compile_regex(const char *regex_string, prepared_pcre_t **pp)
{
        int err_offset;
        const char *err_ptr;

        if ( ! regex_table )
                prelude_hash_new2(&regex_table, 1024, NULL, NULL, NULL, NULL);

        *pp = prelude_hash_get(regex_table, regex_string);
        if ( *pp )
                return 0;

        *pp = malloc(sizeof(**pp));
        if ( ! *pp )
                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "memory exhausted");

        (*pp)->regex = pcre_compile(regex_string, 0, &err_ptr, &err_offset, NULL);
        if ( ! (*pp)->regex ) {
                free(*pp);
                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "unable to compile regex '%s': %s", regex_string, err_ptr);
        }

        (*pp)->extra = pcre_study((*pp)->regex, 0, &err_ptr);
        (*pp)->string = strdup(regex_string);

        prelude_hash_set(regex_table, (*pp)->string, *pp);

        return 0;
}


int match_idmef_path(lua_State *lstate, idmef_message_t *idmef,
                     const char *path, const char *regex,
                     prelude_string_t *outstr, unsigned int *idx,
                     prelude_bool_t flat, prelude_bool_t multipath)
{
        int ret;
        unsigned int lidx = 1;
        prepared_pcre_t *pp;
        idmef_value_t *value;
        idmef_path_t *ipath;
        prelude_bool_t ambiguous;
        struct exec_pcre_cb_data data;

        ret = compile_regex(regex, &pp);
        if ( ret < 0 )
                return ret;

        ret = idmef_path_new_fast(&ipath, path);
        if ( ret < 0 )
                return ret;

        ret = idmef_path_get(ipath, idmef, &value);
        idmef_path_destroy(ipath);

        if ( ret < 0 )
                return ret;

        data.pp = pp;
        data.cb = exec_pcre_cb;
        data.index = idx;
        data.lstate = lstate;
        data.subject = outstr;

        data.flat = flat;
        data.has_top_table = multipath;

        if ( ret == 0 ) {
                prelude_string_set_constant(outstr, "");
                ret = exec_pcre_cb(NULL, &data, FALSE);
                return (ret == PCRE_ERROR_NOMATCH) ? 0 : 1;
        }

        ambiguous = idmef_path_is_ambiguous(ipath);

        if ( flat && multipath && ambiguous ) {
                /*
                 * Multiple path (this function is going to be called
                 * several time), with possibly multiple value, flattened:
                 *
                 * Create a new table holding value for this path, which will
                 * be part of the parent main table.
                 */
                data.index = &lidx;
                lua_pushnumber(lstate, (*idx)++);
                lua_newtable(lstate);
                data.has_top_table = TRUE;
        }

        else if ( flat && ! multipath && ambiguous ) {
                /*
                 * Single path, with possibly multiple value, flattened:
                 * We need a main table to store all the value.
                 */
                lua_newtable(lstate);
                data.has_top_table = TRUE;
        }

        ret = maybe_listed_value_both_cb(value, &data);

        if ( flat && multipath && ambiguous )
                lua_settable(lstate, -3);

        idmef_value_destroy(value);
        return (ret < 0) ? 0 : 1;
}
