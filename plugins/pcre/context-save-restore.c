/*****
*
* Copyright (C) 2006 PreludeIDS Technologies. All Rights Reserved.
* Author: Yoann Vandoorselaere <yoann.v@prelude-ids.com>
*
* This file is part of the Prelude-Correlator program.
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

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

#include <libprelude/prelude.h>
#include <libprelude/prelude-log.h>
#include <libprelude/prelude-extract.h>

#include "pcre-mod.h"
#include "context-save-restore.h"



#define CONTEXT_TAG_NAME                           0
#define CONTEXT_TAG_THRESHOLD                      1

#define CONTEXT_SETTINGS_TAG_TIMEOUT               2
#define CONTEXT_SETTINGS_TAG_FLAGS                 3
#define CONTEXT_SETTINGS_TAG_CORRELATION_WINDOW    4
#define CONTEXT_SETTINGS_TAG_CORRELATION_THRESHOLD 5

#define CONTEXT_TIMER_TAG_ELAPSED                  6
#define CONTEXT_TIMER_TAG_SHUTDOWN                 7

#define CONTEXT_TAG_IDMEF                          8



static void compute_next_expire(prelude_timer_t *timer, unsigned long offtime, unsigned long elapsed)
{        
        if ( offtime + elapsed > prelude_timer_get_expire(timer) )
                prelude_timer_set_expire(timer, 0);
        else
                prelude_timer_set_expire(timer, prelude_timer_get_expire(timer) - (offtime + elapsed));
        
        prelude_timer_reset(timer);
}




static int read_context(pcre_context_t **ctx, pcre_plugin_t *plugin, prelude_msg_t *msg)
{
        int ret;
        void *buf;
        uint8_t tag;
        uint32_t len;
        const char *name;
        idmef_message_t *idmef = NULL;
        pcre_context_setting_t *settings;
        uint32_t threshold, elapsed, shutdown;
        
        settings = calloc(1, sizeof(*settings));
        if ( ! settings )
                return -1;
        
        settings->need_destroy = TRUE;
        
        while ( prelude_msg_get(msg, &tag, &len, &buf) >= 0 ) {
                
                switch (tag) {
                        
                case CONTEXT_TAG_NAME:
                        ret = prelude_extract_characters_safe(&name, buf, len);
                        if ( ret < 0 )
                                goto err;
                        
                        break;
                        
                case CONTEXT_TAG_THRESHOLD:
                        ret = prelude_extract_uint32_safe(&threshold, buf, len);
                        if ( ret < 0 )
                                goto err;

                        break;
                        
                case CONTEXT_SETTINGS_TAG_TIMEOUT:
                        ret = prelude_extract_uint32_safe(&(settings->timeout), buf, len);
                        if ( ret < 0 )
                                goto err;
                        
                        break;
                        
                case CONTEXT_SETTINGS_TAG_FLAGS:
                        ret = prelude_extract_uint32_safe(&settings->flags, buf, len);
                        if ( ret < 0 )
                                goto err;
                        
                        break;
                        
                case CONTEXT_SETTINGS_TAG_CORRELATION_WINDOW:
                        ret = prelude_extract_uint32_safe(&settings->correlation_window, buf, len);
                        if ( ret < 0 )
                                goto err;
                        
                        break;
                        
                case CONTEXT_SETTINGS_TAG_CORRELATION_THRESHOLD:
                        ret = prelude_extract_uint32_safe(&settings->correlation_threshold, buf, len);
                        if ( ret < 0 )
                                goto err;
                        
                        break;

                case CONTEXT_TIMER_TAG_ELAPSED:
                        ret = prelude_extract_uint32_safe(&elapsed, buf, len);
                        if ( ret < 0 )
                                goto err;
                        
                        break;

                case CONTEXT_TIMER_TAG_SHUTDOWN:
                        ret = prelude_extract_uint32_safe(&shutdown, buf, len);
                        if ( ret < 0 )
                                goto err;
                        
                        break;
                        
                case CONTEXT_TAG_IDMEF:
                        ret = idmef_message_new(&idmef);
                        if ( ret < 0 )
                                goto err;

                        idmef_message_set_pmsg(idmef, prelude_msg_ref(msg));
                        
                        ret = idmef_message_read(idmef, msg);
                        if ( ret < 0 ) {
                                idmef_message_destroy(idmef);
                                goto err;
                        }
                        
                        break;
                        
                default:
                        ret = -1;
                        goto err;
                }
        }

        ret = pcre_context_new(ctx, plugin, name, settings);
        if ( idmef ) {
                pcre_context_set_idmef(*ctx, idmef);
                idmef_message_destroy(idmef);
        }
        
        if ( ret < 0 )
                free(settings);
        else {
                prelude_timer_t *timer = pcre_context_get_timer(*ctx);
                
                pcre_context_set_threshold(*ctx, (unsigned int) threshold);
                compute_next_expire(timer, time(NULL) - shutdown, elapsed);
                
        }
        
        
        return ret;

 err:
        free(settings);
        return ret;
}



static int write_context_settings(pcre_context_setting_t *settings, prelude_msgbuf_t *msgbuf)
{
        int ret;
        uint32_t value;

        value = (uint32_t) htonl(settings->timeout);        
        ret = prelude_msgbuf_set(msgbuf, CONTEXT_SETTINGS_TAG_TIMEOUT, sizeof(value), &value);
        if ( ret < 0 )
                return ret;

        value = (uint32_t) htonl(settings->flags);
        ret = prelude_msgbuf_set(msgbuf, CONTEXT_SETTINGS_TAG_FLAGS, sizeof(value), &value);
        if ( ret < 0 )
                return ret;

        value = (uint32_t) htonl(settings->correlation_window);
        ret = prelude_msgbuf_set(msgbuf, CONTEXT_SETTINGS_TAG_CORRELATION_WINDOW, sizeof(value), &value);
        if ( ret < 0 )
                return ret;

        value = (uint32_t) htonl(settings->correlation_threshold);
        ret = prelude_msgbuf_set(msgbuf, CONTEXT_SETTINGS_TAG_CORRELATION_THRESHOLD, sizeof(value), &value);
        if ( ret < 0 )
                return ret;
        
        return 0;
}



static int write_context(pcre_context_t *context, prelude_msgbuf_t *msgbuf)
{
        int ret;
        time_t now;
        uint32_t value;
        const char *cname = pcre_context_get_name(context);
        prelude_timer_t *timer = pcre_context_get_timer(context);
        
        ret = prelude_msgbuf_set(msgbuf, CONTEXT_TAG_NAME, strlen(cname) + 1, cname);
        if ( ret < 0 )
                return ret;

        now = time(NULL);
        
        value = (uint32_t) htonl(pcre_context_get_threshold(context));
        ret = prelude_msgbuf_set(msgbuf, CONTEXT_TAG_THRESHOLD, sizeof(value), &value);
        if ( ret < 0 )
                return ret;

        value = (uint32_t) htonl(now - timer->start_time);
        ret = prelude_msgbuf_set(msgbuf, CONTEXT_TIMER_TAG_ELAPSED, sizeof(value), &value);
        if ( ret < 0 )
                return ret;

        value = (uint32_t) htonl(now);
        ret = prelude_msgbuf_set(msgbuf, CONTEXT_TIMER_TAG_SHUTDOWN, sizeof(value), &value);
        if ( ret < 0 )
                return ret;
        
        return write_context_settings(pcre_context_get_setting(context), msgbuf);
}



static int flush_msgbuf_cb(prelude_msgbuf_t *msgbuf, prelude_msg_t *msg)
{        
        int ret;
        
        ret = prelude_msg_write(msg, prelude_msgbuf_get_data(msgbuf));
        prelude_msg_recycle(msg);

        return ret;
}



int pcre_context_save(prelude_plugin_instance_t *pi, pcre_context_t *context)
{
        int ret;
        FILE *fd;
        prelude_io_t *io;
        char filename[PATH_MAX];
        prelude_msgbuf_t *msgbuf;
        const char *name = pcre_context_get_name(context);

        snprintf(filename, sizeof(filename), PRELUDE_CORRELATOR_CONTEXT_DIR "/pcre[%s]",
                 prelude_plugin_instance_get_name(pi));

        fd = fopen(filename, "a");
        if ( ! fd ) {
                prelude_log(PRELUDE_LOG_ERR, "error saving context '%s': %s.\n", name, strerror(errno));
                return -1;
        }

        ret = prelude_io_new(&io);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "error creating IO object: %s.\n", strerror(errno));
                return ret;
        }
        
        prelude_io_set_file_io(io, fd);
        
        ret = prelude_msgbuf_new(&msgbuf);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "error creating message buffer: %s.\n", strerror(errno));
                goto err;
        }

        prelude_msgbuf_set_data(msgbuf, io);
        prelude_msgbuf_set_callback(msgbuf, flush_msgbuf_cb);
                
        ret = write_context(context, msgbuf);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "error writing context: %s.\n", strerror(errno));
                goto err;
        }

        if ( pcre_context_get_idmef(context) ) {
                ret = prelude_msgbuf_set(msgbuf, CONTEXT_TAG_IDMEF, 0, NULL);
                if ( ret < 0 ) {
                        prelude_perror(ret, "error writing IDMEF message");
                        goto err;
                }
                
                ret = idmef_message_write(pcre_context_get_idmef(context), msgbuf);
                if ( ret < 0 ) {
                        prelude_perror(ret, "error writing IDMEF message");
                        goto err;
                }
        }
        
                
        prelude_msgbuf_mark_end(msgbuf);

 err:
        prelude_msgbuf_destroy(msgbuf);
        prelude_io_close(io);
        prelude_io_destroy(io);

        if ( ret < 0 )
                unlink(name);
        
        return ret;
}




unsigned int pcre_context_restore(prelude_plugin_instance_t *plugin)
{
        int ret;
        FILE *fd;
        prelude_io_t *io;
        prelude_msg_t *msg;
        pcre_context_t *ctx;
        char filename[PATH_MAX];
        unsigned int restored_context_count = 0;
        
        ret = prelude_io_new(&io);
        if ( ret < 0 )
                return ret;

        snprintf(filename, sizeof(filename), PRELUDE_CORRELATOR_CONTEXT_DIR "/pcre[%s]",
                 prelude_plugin_instance_get_name(plugin));
        
        fd = fopen(filename, "r");                
        if ( ! fd ) {
                if ( errno == ENOENT )
                        return 0;
                
                prelude_log(PRELUDE_LOG_ERR, "error opening '%s' for reading: %s.\n", filename, strerror(errno));
                return -1;
        }

        prelude_io_set_file_io(io, fd);

        do {
                msg = NULL;

                ret = prelude_msg_read(&msg, io);
                if ( ret < 0 ) {
                        if ( prelude_error_get_code(ret) == PRELUDE_ERROR_EOF )
                                break;
                        
                        prelude_perror(ret, "error reading '%s'", filename);
                        continue;
                }

                ret = read_context(&ctx, prelude_plugin_instance_get_plugin_data(plugin), msg);
                prelude_msg_destroy(msg);
                
                if ( ret < 0 ) {
                        prelude_perror(ret, "error decoding '%s'", filename);
                        continue;
                }

                restored_context_count++;
        } while (TRUE);
        
        prelude_io_close(io);
        prelude_io_destroy(io);
        
        ret = unlink(filename);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "error unlinking '%s': %s.\n", filename, strerror(errno));
                return -1;
        }
        
        return restored_context_count;
}
