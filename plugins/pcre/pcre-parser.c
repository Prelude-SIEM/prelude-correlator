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

#include <stdio.h>
#include <ctype.h>
#include <string.h>

#include <libprelude/prelude.h>

#include "pcre-mod.h"
#include "pcre-parser.h"


/*
 * <operation> <variable> = <value>
 * <operation> = <value>
 * <variable> = <value>
 *
 * global $WORM = stuff
 * new_context = stuff
 * $WORM = stuff
 */


static prelude_bool_t is_equal(const char *ptr)
{
        if ( ! isspace(*(ptr - 1)) && ! isalnum(*(ptr - 1)) )
                return FALSE;

        if ( ! isspace(*(ptr + 1)) && ! isalnum(*(ptr + 1)) )
                return FALSE;

        return TRUE;
}


static int parse_variable_and_value(const char *filename, unsigned int *line, char *input, char **key, char **value) 
{
        size_t len;
        char *ptr, *tmp;
        
        *value = NULL;
        *key = input;

        if ( *input == '=' )
                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "no keyword specified, but assignement found");
        
        /*
         * search first '=' in the input,
         * corresponding to the key = value separator.
         */
        len = strcspn(input, "=;");
        if ( len == strlen(input) || ! is_equal(input + len) ) {
                len = strcspn(input, " ");
        }
        
        tmp = ptr = input + len;

        /*
         * strip whitespace at the tail of the key.
         */
        while ( tmp && (*tmp == '=' || *tmp == ':' || *tmp == ';' || isspace((int) *tmp)) )
                *tmp-- = '\0';
        
        /*
         * strip whitespace at the begining of the value.
         */
        ptr++;
        while ( *ptr != '\0' && isspace((int) *ptr) )
                ptr++;

        *value = ptr;

        /*
         * strip whitespace at the end of the value.
         */
        ptr = ptr + strlen(ptr) - 1;
        while ( isspace((int) *ptr) )
                *ptr-- = '\0';

        if ( *ptr == ';' )
                *ptr = 0;
        
        return 0;
}

        
static int parse_input(const char *filename, unsigned int *line,
                       char *input, char **operation, char **variable, char **value) 
{
        char *ptr;
        
        *variable = *value = NULL;
        ptr = input + strcspn(input, " ");
        
        if ( *input == '$' ) {
                *operation = NULL;
                return parse_variable_and_value(filename, line, input, variable, value);
        }

        else if ( ptr != input && *(ptr + 1) == '$' ) {
                *ptr = 0;
                *operation = input;
                return parse_variable_and_value(filename, line, ptr + 1, variable, value);
        }
        
        else {
                *variable = NULL;
                return parse_variable_and_value(filename, line, input, operation, value);
        }
        
        return 0;
}


int pcre_parse(FILE *fd, const char *filename, unsigned int *line, char **operation, char **variable, char **value)
{
        int ret;
        char buf[8192], *ptr;

        
        while ( prelude_read_multiline(fd, line, buf, sizeof(buf)) == 0 ) {
                
                /*
                 * filter space and tab at the begining of the line.
                 */
                for ( ptr = buf; isspace(*ptr); ptr++ );

                /*
                 * empty line or comment. 
                 */
                if ( *ptr == '\0' || *ptr == '#' )
                        continue;

                if ( *ptr == '}' )
                        return 0;
                
                ret = parse_input(filename, line, ptr, operation, variable, value);
                if ( ret < 0 )
                        return ret;

                if ( *operation )
                        *operation = strdup(*operation);

                if ( *variable )
                        *variable = strdup(*variable + 1);

                *value = strdup(*value);
                return 1;
        }
        
        return 0;
}
