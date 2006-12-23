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

#include "config.h"

#include <stdlib.h>
#include <string.h>

#include <libprelude/prelude.h>
#include <libprelude/prelude-log.h>
#include <libprelude/idmef-message-print.h>

#include "prelude-correlator.h"
#include "correlation-plugins.h"

#define CLIENT_NAME      "prelude-correlator"
#define ANALYZER_MODEL   "prelude-correlator"
#define ANALYZER_CLASS   "Correlator"

static const char *config_file = PRELUDE_CORRELATOR_CONF;


static char **global_argv;
static struct timeval start;
static unsigned long alert_count = 0;
static unsigned long message_processed = 0;
static volatile sig_atomic_t got_signal = 0;


static prelude_bool_t dry_run = FALSE;
static prelude_client_t *client = NULL;
static prelude_io_t *print_input_fd = NULL;
static prelude_io_t *print_output_fd = NULL;


static void print_stats(const char *prefix, struct timeval *end)
{
        double tdiv;

        tdiv = (end->tv_sec + (double) end->tv_usec / 1000000) - (start.tv_sec + (double) start.tv_usec / 1000000);
                
        prelude_log(PRELUDE_LOG_WARN, "%s%u message processed in %.2f seconds (%.2f EPS), %d alert emited.\n",
                    prefix, message_processed, tdiv, message_processed / tdiv, alert_count);
}



static RETSIGTYPE sig_handler(int signum)
{
        got_signal = signum;      
}



static int set_print_help(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        prelude_option_print(NULL, PRELUDE_OPTION_TYPE_CLI, 25, stderr);
        return prelude_error(PRELUDE_ERROR_EOF);
}



static int set_print_input(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        int ret;
        FILE *fd;
        
        ret = prelude_io_new(&print_input_fd);
        if ( ret < 0 ) {
                prelude_perror(ret, "error creating descriptor");
                return -1;
        }

        if ( ! optarg || *optarg == '-' )
                fd = stdout;
        else {
                fd = fopen(optarg, "w");
                if ( ! fd ) {
                        prelude_log(PRELUDE_LOG_ERR, "error opening '%s': %s.\n", optarg, strerror(errno));
                        return -1;
                }
        }
        
        prelude_io_set_file_io(print_input_fd, stdout);

        return 0;
}



static int set_print_output(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        int ret;
        FILE *fd;
        
        ret = prelude_io_new(&print_output_fd);
        if ( ret < 0 ) {
                prelude_perror(ret, "error creating descriptor");
                return -1;
        }

        if ( ! optarg || *optarg == '-' )
                fd = stdout;
        else {
                fd = fopen(optarg, "w");
                if ( ! fd ) {
                        prelude_log(PRELUDE_LOG_ERR, "error opening '%s': %s.\n", optarg, strerror(errno));
                        return -1;
                }
        }
        
        prelude_io_set_file_io(print_output_fd, stdout);

        return 0;
}



static int set_debug_level(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        int level = (optarg) ? atoi(optarg) : PRELUDE_LOG_DEBUG;
        prelude_log_set_debug_level(level);
        return 0;
}


static int set_dry_run(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        dry_run = TRUE;
        return 0;
}


static int set_conf_file(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        config_file = strdup(optarg);
        return 0;
}


static int init_options(prelude_option_t *ropt, int argc, char **argv)
{
        int ret;
        prelude_string_t *err;
        prelude_option_t *opt;
        
        prelude_option_add(ropt, NULL, PRELUDE_OPTION_TYPE_CLI, 'h', "help",
                           "Print this help", PRELUDE_OPTION_ARGUMENT_OPTIONAL,
                           set_print_help, NULL);

        prelude_option_add(ropt, &opt, PRELUDE_OPTION_TYPE_CLI, 'c', "config",
                           "Configuration file to use", PRELUDE_OPTION_ARGUMENT_REQUIRED,
                           set_conf_file, NULL);
        prelude_option_set_priority(opt, PRELUDE_OPTION_PRIORITY_IMMEDIATE);
        
        prelude_option_add(ropt, NULL, PRELUDE_OPTION_TYPE_CLI, 0, "dry-run",
                           "No report to the specified Manager will occur.", PRELUDE_OPTION_ARGUMENT_OPTIONAL,
                           set_dry_run, NULL);
        
        prelude_option_add(ropt, NULL, PRELUDE_OPTION_TYPE_CLI, 0, "print-input",
                           "Dump alert input from manager to the specified file", PRELUDE_OPTION_ARGUMENT_OPTIONAL,
                           set_print_input, NULL);
        
        prelude_option_add(ropt, NULL, PRELUDE_OPTION_TYPE_CLI, 0, "print-output",
                           "Dump alert output to the specified file", PRELUDE_OPTION_ARGUMENT_OPTIONAL,
                           set_print_output, NULL);

        prelude_option_add(ropt, NULL, PRELUDE_OPTION_TYPE_CLI, 0, "debug",
                           "Enable debug ouptut (optional debug level argument)", PRELUDE_OPTION_ARGUMENT_OPTIONAL,
                           set_debug_level, NULL);

        ret = prelude_option_read(ropt, &config_file, &argc, argv, &err, NULL);
        if ( ret < 0 ) {
                if ( prelude_error_get_code(ret) == PRELUDE_ERROR_EOF )
                        return -1;
                
                if ( err )
                        prelude_log(PRELUDE_LOG_WARN, "%s.\n", prelude_string_get_string(err));
                else
                        prelude_perror(ret, "error processing options");
                
                return -1;
        }
        
        return 0;
}



static const char *get_restart_string(void)
{
        int ret;
        size_t i;
        prelude_string_t *buf;
        
        ret = prelude_string_new(&buf);
        if ( ret < 0 )
                return global_argv[0];
        
        for ( i = 0; global_argv[i] != NULL; i++ ) {
                if ( ! prelude_string_is_empty(buf) )
                        prelude_string_cat(buf, " ");
                        
                prelude_string_cat(buf, global_argv[i]);
        }

        return prelude_string_get_string(buf);
}


static void handle_sigquit(void)
{
        struct timeval end;
        
        gettimeofday(&end, NULL);
        print_stats("statistics signal received: ", &end);
}



static void handle_sighup(void) 
{
        int ret;

        /*
         * Here we go !
         */
        ret = execvp(global_argv[0], global_argv);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "error re-executing lml\n");
                return;
        }
}


static void handle_signal_if_needed(void)
{
        int signo;
        
        if ( ! got_signal )
                return;

        signo = got_signal;
        got_signal = 0;

        if ( signo == SIGHUP ) {
                prelude_log(PRELUDE_LOG_WARN, "signal %d received, restarting (%s).\n", signo, get_restart_string());
                handle_sighup();
        }
        
        if ( signo == SIGQUIT || signo == SIGUSR1 ) {
                handle_sigquit();
                return;
        }
        
        prelude_log(PRELUDE_LOG_WARN, "signal %d received, terminating prelude-correlator.\n", signo);
        
        correlation_plugins_destroy();
        exit(1);
}



static int poll_manager(prelude_connection_pool_t *pool)
{
        int ret;
        prelude_msg_t *msg;
        idmef_message_t *idmef;
        prelude_connection_t *conn;
        
        do {
                msg = NULL;
                
                ret = prelude_connection_pool_recv(pool, 1, &conn, &msg);
                prelude_timer_wake_up();
                handle_signal_if_needed();

                if ( ret == 0 )
                        continue;
                
                if ( ret < 0 ) {
                        if ( prelude_error_get_code(ret) != PRELUDE_ERROR_EINTR )
                                prelude_perror(ret, "error polling connection pool");
                        
                        continue;
                }

                ret = idmef_message_new(&idmef);
                if ( ret < 0 ) {
                        prelude_msg_destroy(msg);
                        prelude_perror(ret, "error creating IDMEF object");
                        continue;
                }
                
                ret = idmef_message_read(idmef, msg);
                if ( ret < 0 ) {
                        prelude_msg_destroy(msg);
                        idmef_message_destroy(idmef);                        
                        prelude_perror(ret, "error reading prelude message");
                        continue;
                }
                
                if ( print_input_fd )
                        idmef_message_print(idmef, print_input_fd);

                correlation_plugins_run(idmef);
                
                idmef_message_destroy(idmef);
                prelude_msg_destroy(msg);

                message_processed++;

        } while ( 1 );
}



static void setup_signal(void)
{
        struct sigaction action;
        
        /*
         * setup signal handling
         */
        action.sa_flags = 0;
        sigemptyset(&action.sa_mask);
        action.sa_handler = sig_handler;
        
#ifdef SA_INTERRUPT
        action.sa_flags |= SA_INTERRUPT;
#endif

        sigaction(SIGTERM, &action, NULL);
        sigaction(SIGINT, &action, NULL);
        sigaction(SIGQUIT, &action, NULL);
        sigaction(SIGABRT, &action, NULL);
        sigaction(SIGUSR1, &action, NULL);
        sigaction(SIGQUIT, &action, NULL);
        sigaction(SIGHUP, &action, NULL);
}




void correlation_alert_emit(idmef_message_t *idmef)
{
        idmef_alert_t *alert;
        idmef_analyzer_t *analyzer = NULL;
        
        alert = idmef_message_get_alert(idmef);
        if ( ! alert )
                return;

        idmef_alert_set_messageid(alert, NULL);
        
        if ( ! dry_run ) {
                analyzer = idmef_analyzer_ref(prelude_client_get_analyzer(client));
                
                idmef_alert_set_analyzer(alert, analyzer, IDMEF_LIST_APPEND);
                prelude_client_send_idmef(client, idmef);
        }
        
        if ( print_output_fd )
                idmef_message_print(idmef, print_output_fd);

        if ( analyzer )
                prelude_linked_object_del_init((prelude_linked_object_t *) analyzer);
}



int main(int argc, char **argv)
{
        int ret;
        prelude_string_t *str;
        idmef_analyzer_t *analyzer;
        prelude_option_t *root_option;

        global_argv = argv;
        setup_signal();

        ret = prelude_init(&argc, argv);
        if ( ret < 0 ) {
                prelude_perror(ret, "error initializing libprelude");
                return -1;
        }

        ret = prelude_option_new_root(&root_option);
        if ( ret < 0 )
                return -1;
        
        ret = correlation_plugins_init(root_option);
        if ( ret < 0 )
                return -1;
        
        ret = init_options(root_option, argc, argv);
        if ( ret < 0 )
                return -1;

        ret = prelude_client_new(&client, CLIENT_NAME);
        if ( ret < 0 ) {
                prelude_perror(ret, "error creating prelude client");
                return -1;
        }

        prelude_client_set_required_permission(client, PRELUDE_CONNECTION_PERMISSION_IDMEF_READ|
                                               PRELUDE_CONNECTION_PERMISSION_IDMEF_WRITE);
        
        analyzer = prelude_client_get_analyzer(client);
        
        prelude_string_new_constant(&str, ANALYZER_MODEL);
        idmef_analyzer_set_model(analyzer, str);
        
        prelude_string_new_constant(&str, ANALYZER_CLASS);
        idmef_analyzer_set_model(analyzer, str);
        
        prelude_string_new_constant(&str, VERSION);
        idmef_analyzer_set_model(analyzer, str);
        
        ret = prelude_client_start(client);
        if ( ret < 0 ) {
                prelude_perror(ret, "error starting prelude client");
                return -1;
        }
        
        gettimeofday(&start, NULL);
        return poll_manager(prelude_client_get_connection_pool(client));
}
