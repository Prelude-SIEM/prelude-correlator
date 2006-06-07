/*****
*
* Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006 PreludeIDS Technologies. All Rights Reserved.
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
#include <sys/time.h>
#include <pcre.h>
#include <netdb.h>
#include <libprelude/prelude-log.h>

#include "prelude-correlator.h"
#include "pcre-mod.h"
#include "rule-object.h"
#include "rule-regex.h"


int pcre_LTX_prelude_plugin_version(void);
int pcre_LTX_correlation_plugin_init(prelude_plugin_entry_t *pe, void *data);



struct pcre_plugin {
        int rulesnum;
        char *rulesetdir;
        int last_rules_first;
        prelude_bool_t dump_unmatched;
        
        prelude_list_t rule_list;
        prelude_list_t context_list;
};



struct pcre_context {
        prelude_list_t list;
        
        char *name;
        prelude_timer_t timer;
        pcre_context_setting_t *setting;

        unsigned int threshold;
        idmef_message_t *idmef;
};



static void free_rule_container(pcre_rule_container_t *rc);
static int parse_ruleset(prelude_list_t *head, pcre_plugin_t *plugin, const char *filename, FILE *fd);




static PRELUDE_LIST(chained_rule_list);
static prelude_correlator_plugin_t pcre_plugin;


static int parse_key_and_value(char *input, char **key, char **value) 
{
        char *ptr, *tmp;

        *value = NULL;
        
        /*
         * filter space at the begining of the line.
         */
        while ( (*input == ' ' || *input == '\t') && *input != '\0' )
                input++;

        if ( *input == '\0' )
                return 0;
        
        *key = input;

        /*
         * search first '=' in the input,
         * corresponding to the key = value separator.
         */
        tmp = ptr = input + strcspn(input, "=:;");
        
        /*
         * strip whitespace at the tail of the key.
         */
        while ( tmp && (*tmp == '=' || *tmp == ':' || *tmp == ';' || isspace((int) *tmp)) )
                *tmp-- = '\0';

        if ( ! ptr )
                /* key without value */
                return 0; 
        
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


static int parse_multiple_key_and_value(const char **input, char **key, char **value)
{
        int ret;
        char *ptr;
        union { char **rw; const char **ro; } val;

        val.ro = input;
        
        ptr = strsep(val.rw, ";");
        if ( ! ptr )
                return 0;

        ret = parse_key_and_value(ptr, key, value);
        if ( ret < 0 )
                return ret;

        return 1;
}


static pcre_rule_container_t *create_rule_container(pcre_rule_t *rule)
{
        pcre_rule_container_t *rc;

        rc = calloc(1, sizeof(*rc));
        if ( ! rc ) {
                prelude_log(PRELUDE_LOG_ERR, "memory exhausted.\n");
                return NULL;
        }
        
        rc->rule = rule;
        rule->refcount++;
        
        return rc;
}



static int parse_rule_id(pcre_plugin_t *plugin, pcre_rule_t *rule, const char *id) 
{
        rule->id = (unsigned int) strtoul(id, NULL, 0);

        return 0;
}



static int parse_rule_revision(pcre_plugin_t *plugin, pcre_rule_t *rule, const char *revision) 
{
        rule->revision = (unsigned int) strtoul(revision, NULL, 0);

        return 0;
}


static pcre_rule_container_t *search_rule(prelude_list_t *head, int id)
{
        prelude_list_t *tmp;
        pcre_rule_container_t *cur;
        
        prelude_list_for_each(head, tmp) {
                cur = prelude_list_entry(tmp, pcre_rule_container_t, list);
                
                if ( cur->rule->id == id )
                        return cur;
                
                cur = search_rule(&cur->rule->rule_list, id);
                if ( cur )
                        return cur;
        }

        return NULL;
}



static int add_goto_single(pcre_plugin_t *plugin, pcre_rule_t *rule, int id, prelude_bool_t optional)
{
        pcre_rule_container_t *new, *cur;

        cur = search_rule(&chained_rule_list, id);
        if ( ! cur ) {
                cur = search_rule(&plugin->rule_list, id);
                if ( ! cur ) {
                        prelude_log(PRELUDE_LOG_WARN, "could not find a rule with ID %d.\n", id);
                        return -1;
                }
        }
        
        new = create_rule_container(cur->rule);
        if ( ! new ) 
                return -1;

        if ( optional )
                new->optional = TRUE;
                
        prelude_list_add_tail(&rule->rule_list, &new->list);

        return 0;
}


static int add_goto(pcre_plugin_t *plugin, pcre_rule_t *rule, const char *idstr, prelude_bool_t optional)
{
        int ret, i, idmin = 0, idmax = 0;
        
        ret = sscanf(idstr, "%d-%d", &idmin, &idmax);
        if ( ret < 1 ) {
                prelude_log(PRELUDE_LOG_WARN, "could not parse goto value '%s'.\n", idstr);
                return -1;
        }

        if ( ret == 1 )
                idmax = idmin;
                
        for ( i = idmin; i <= idmax; i++ ) {
                
                ret = add_goto_single(plugin, rule, i, optional);
                if ( ret < 0 )
                        return -1;
        }

        return 0;
}


static int parse_rule_goto(pcre_plugin_t *plugin, pcre_rule_t *rule, const char *idstr)
{
        return add_goto(plugin, rule, idstr, FALSE);
}



static int parse_rule_optgoto(pcre_plugin_t *plugin, pcre_rule_t *rule, const char *idstr)
{
        return add_goto(plugin, rule, idstr, TRUE);
}



static int parse_rule_min_optgoto_match(pcre_plugin_t *plugin, pcre_rule_t *rule, const char *arg)
{
        rule->min_optgoto_match = atoi(arg);

        return 0;
}



static int parse_rule_last(pcre_plugin_t *plugin, pcre_rule_t *rule, const char *arg)
{
        rule->flags |= PCRE_RULE_FLAGS_LAST;
        return 0;
}




static int parse_rule_silent(pcre_plugin_t *plugin, pcre_rule_t *rule, const char *arg)
{        
        rule->flags |= PCRE_RULE_FLAGS_SILENT;
        return 0;
}


static int parse_rule_chained(pcre_plugin_t *plugin, pcre_rule_t *rule, const char *arg)
{
        rule->flags |= PCRE_RULE_FLAGS_CHAINED;
        return 0;
}


static int parse_require_context(pcre_plugin_t *plugin, pcre_rule_t *rule, const char *arg)
{
        return value_container_new(&rule->required_context, arg);
}



static int parse_optional_context(pcre_plugin_t *plugin, pcre_rule_t *rule, const char *arg)
{
        return value_container_new(&rule->optional_context, arg);
}



static int add_value_to_list(prelude_list_t *head, const char *arg, void *data)
{
        int ret;
        value_container_t *vcont;

        ret = value_container_new(&vcont, arg);
        if ( ret < 0 )
                return ret;

        value_container_set_data(vcont, data);
        prelude_linked_object_add_tail(head, (prelude_linked_object_t *) vcont);

        return 0;
}


static int _parse_create_context(pcre_rule_t *rule, const char *arg, pcre_context_setting_flags_t flags)
{
        int ret;
        char *key, *value;
        const char *cname = NULL;
        pcre_context_setting_t *pcs;
        
        pcs = calloc(1, sizeof(*pcs));
        if ( ! pcs )
                return -1;

        pcs->timeout = 60;
        pcs->flags = flags;

        while ( (ret = parse_multiple_key_and_value(&arg, &key, &value)) == 1 ) {                
                
                if ( ! cname )
                        cname = key;
                
                else if ( strcmp(key, "alert_on_destroy") == 0 )
                        pcs->flags |= PCRE_CONTEXT_SETTING_FLAGS_ALERT_ON_DESTROY;
                
                else if ( strcmp(key, "alert_on_expire") == 0 )
                        pcs->flags |= PCRE_CONTEXT_SETTING_FLAGS_ALERT_ON_EXPIRE;
                
                else if ( strcmp(key, "threshold") == 0 )
                        pcs->correlation_threshold = atoi(value);
                
                else if ( strcmp(key, "expire") == 0 )
                        pcs->timeout = atoi(value);
                
                else {
                        free(pcs);
                        prelude_log(PRELUDE_LOG_WARN, "Unknown context creation argument: '%s'.\n", key);
                        return -1;
                }
        }

        if ( ret == 0 )
                ret = add_value_to_list(&rule->create_context_list, cname, pcs);

        if ( ret < 0 )
                free(pcs);
        
        return ret;
}


static int parse_create_context(pcre_plugin_t *plugin, pcre_rule_t *rule, const char *arg)
{
        return _parse_create_context(rule, arg, 0);
}


static int parse_set_context(pcre_plugin_t *plugin, pcre_rule_t *rule, const char *arg)
{
        return _parse_create_context(rule, arg, PCRE_CONTEXT_SETTING_FLAGS_OVERWRITE);
}


static int parse_add_context(pcre_plugin_t *plugin, pcre_rule_t *rule, const char *arg)
{
        return _parse_create_context(rule, arg, PCRE_CONTEXT_SETTING_FLAGS_QUEUE);
}


static int parse_not_context(pcre_plugin_t *plugin, pcre_rule_t *rule, const char *arg)
{
        int ret;
        value_container_t *vcont;
        
        ret = value_container_new(&vcont, arg);
        if ( ret < 0 )
                return ret;

        prelude_linked_object_add_tail(&rule->not_context_list, (prelude_linked_object_t *) vcont);

        return 0;
}


static int parse_destroy_context(pcre_plugin_t *plugin, pcre_rule_t *rule, const char *arg)
{
        return add_value_to_list(&rule->destroy_context_list, arg, NULL);
}


static int parse_threshold(pcre_plugin_t *plugin, pcre_rule_t *rule, const char *arg)
{
        value_container_t *ctx;
        pcre_context_setting_t *setting;

        ctx = (rule->required_context) ? rule->required_context : rule->optional_context;
        if ( ! ctx ) {
                prelude_log(PRELUDE_LOG_WARN, "'threshold' set but no context specified.\n");
                return -1;
        }

        setting = value_container_get_data(ctx);
        if ( ! setting ) {
                setting = calloc(1, sizeof(*setting));
                if ( ! setting ) {
                        prelude_log(PRELUDE_LOG_ERR, "memory exhausted.\n");
                        return -1;
                }

                value_container_set_data(ctx, setting);
        }

        setting->correlation_threshold = atoi(arg);
        return 0;
}



static int parse_window(pcre_plugin_t *plugin, pcre_rule_t *rule, const char *arg)
{
        pcre_context_setting_t *setting;
                
        if ( ! rule->required_context ) {
                prelude_log(PRELUDE_LOG_WARN, "'window' set but no context specified.\n");
                return -1;
        }

        setting = value_container_get_data(rule->required_context);
        if ( ! setting ) {
                setting = calloc(1, sizeof(*setting));
                if ( ! setting ) {
                        prelude_log(PRELUDE_LOG_ERR, "memory exhausted.\n");
                        return -1;
                }

                value_container_set_data(rule->required_context, setting);
        }

        setting->correlation_window = atoi(arg);

        return 0;
}


static int parse_pattern(pcre_plugin_t *plugin, pcre_rule_t *rule, const char *arg)
{
        int ret;
        rule_regex_t *new;
        char *value, *key;
               
        do {
                ret = parse_multiple_key_and_value(&arg, &key, &value);
                if ( ret != 1 )
                        return ret;
                
                new = rule_regex_new(key, value);
                if ( ! new )
                        return -1;
                
                prelude_linked_object_add_tail(&rule->regex_list, (prelude_linked_object_t *) new);
        } while ( 1 );

        return 0;
}



static int action_parse(struct rule_object_list *object_list, const char *arg)
{
        int ret;
        char *key, *value;
        
        do {
                ret = parse_multiple_key_and_value(&arg, &key, &value);
                if ( ret != 1 )
                        return ret;
                
                ret = rule_object_add(object_list, NULL, 0, key, value); 
                if ( ret < 0 )
                        return ret;
        } while ( 1 );

        return 0;  
}



static int parse_action(pcre_plugin_t *plugin, pcre_rule_t *rule, const char *arg)
{
        return action_parse(rule->action_object_list, arg);
}



static int parse_pre_action(pcre_plugin_t *plugin, pcre_rule_t *rule, const char *arg)
{
        return action_parse(rule->pre_action_object_list, arg);
}


static int parse_include(pcre_rule_t *rule, pcre_plugin_t *plugin, const char *value) 
{
        int ret;
        FILE *fd;
        char filename[256];

        if ( plugin->rulesetdir && value[0] != '/' )
                snprintf(filename, sizeof(filename), "%s/%s", plugin->rulesetdir, value);
        else
                snprintf(filename, sizeof(filename), "%s", value);

        fd = fopen(filename, "r");
        if ( ! fd ) {
                prelude_log(PRELUDE_LOG_ERR, "couldn't open %s for reading: %s.\n", filename, strerror(errno));
                return -1;
        }
        
        ret = parse_ruleset(rule ? &rule->rule_list : &plugin->rule_list, plugin, filename, fd);
        fclose(fd);

        return ret;
}


static int parse_rule_included(pcre_plugin_t *plugin, pcre_rule_t *rule, const char *value)
{
        int ret;
        prelude_list_t *t;
        pcre_rule_container_t tmp, *cur;
        
        tmp.rule = rule;
        prelude_list_add(&plugin->rule_list, &tmp.list);
        
        ret = parse_include(rule, plugin, value);
        prelude_list_del(&tmp.list);
        
        prelude_list_for_each(&rule->rule_list, t) {
                cur = prelude_list_entry(t, pcre_rule_container_t, list);
                cur->optional = 1;
        }
        
        return ret;
}
        

static int parse_rule_keyword(pcre_plugin_t *plugin, pcre_rule_t *rule,
                              const char *filename, int line,
                              const char *keyword, const char *value)
{
        int i;
        struct {
                const char *keyword;
                int (*func)(pcre_plugin_t *plugin, pcre_rule_t *rule, const char *value);
        } keywords[] = {
                { "chained"             , parse_rule_chained            },
                { "goto"                , parse_rule_goto               },
                { "id"                  , parse_rule_id                 },
                { "last"                , parse_rule_last               },
                { "min-optgoto-match"   , parse_rule_min_optgoto_match  },
                { "optgoto"             , parse_rule_optgoto            },
                { "revision"            , parse_rule_revision           },
                { "silent"              , parse_rule_silent             },
                { "include"             , parse_rule_included           },
                { "new_context"         , parse_create_context          },
                { "set_context"         , parse_set_context             },
                { "add_context"         , parse_add_context             },
                { "not_context"         , parse_not_context             },
                { "destroy_context"     , parse_destroy_context         },
                { "require_context"     , parse_require_context         },
                { "optional_context"    , parse_optional_context        },
                { "threshold"           , parse_threshold               },
                { "window"              , parse_window                  },
                { "pattern"             , parse_pattern                 },
                { "action"              , parse_action                  },
                { "pre_action"          , parse_pre_action              }
        };
        
        for ( i = 0; i < sizeof(keywords) / sizeof(keywords[0]); i++ ) {
                if ( strcmp(keyword, keywords[i].keyword) != 0 )
                        continue;

                if ( keywords[i].func(plugin, rule, value) < 0 ) {
                        prelude_log(PRELUDE_LOG_WARN, "%s:%d: error parsing value for '%s'.\n", filename, line, keyword);
                        return -1;
                }

                return 1;
        }

        return 0;
}




static pcre_rule_t *create_rule(void)
{
        pcre_rule_t *rule;

        rule = calloc(1, sizeof(*rule));
        if ( ! rule ) {
                prelude_log(PRELUDE_LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        rule->action_object_list = rule_object_list_new();
        if ( ! rule->action_object_list ) {
                free(rule);
                return NULL;
        }

        
        rule->pre_action_object_list = rule_object_list_new();
        if ( ! rule->pre_action_object_list ) {
                rule_object_list_destroy(rule->action_object_list);
                free(rule);
                return NULL;
        }

        prelude_list_init(&rule->rule_list);
        prelude_list_init(&rule->regex_list);
        prelude_list_init(&rule->not_context_list);
        prelude_list_init(&rule->create_context_list);
        prelude_list_init(&rule->destroy_context_list);
                
        return rule;
}



static void free_rule(pcre_rule_t *rule) 
{
        rule_regex_t *item;
        prelude_list_t *tmp, *bkp;
        pcre_rule_container_t *rc;
        
        prelude_list_for_each_safe(&rule->rule_list, tmp, bkp) {
                rc = prelude_list_entry(tmp, pcre_rule_container_t, list);
                free_rule_container(rc);
        }
        
        prelude_list_for_each_safe(&rule->regex_list, tmp, bkp) {
                item = prelude_linked_object_get_object(tmp);
                rule_regex_destroy(item);
        }

        rule_object_list_destroy(rule->action_object_list);
        rule_object_list_destroy(rule->pre_action_object_list);
                                        
        free(rule);
}



static void free_rule_container(pcre_rule_container_t *rc)
{
        if ( --rc->rule->refcount == 0 )
                free_rule(rc->rule);
        
        prelude_list_del(&rc->list);
        free(rc);
}



static int add_rule(pcre_plugin_t *plugin, pcre_rule_t *rule)
{
        pcre_rule_container_t *rc;
        
        rc = create_rule_container(rule);
        if ( ! rc ) {
                free_rule(rule);
                return -1;
        }

        if ( rule->flags & PCRE_RULE_FLAGS_CHAINED )
                prelude_list_add(&chained_rule_list, &rc->list);
        
        else if ( plugin->last_rules_first && rule->flags & PCRE_RULE_FLAGS_LAST )
                prelude_list_add(&plugin->rule_list, &rc->list);
        else
                prelude_list_add_tail(&plugin->rule_list, &rc->list);
        
        plugin->rulesnum++;

        return 0;
}



static int parse_ruleset(prelude_list_t *head, pcre_plugin_t *plugin, const char *filename, FILE *fd) 
{
        int ret;
        char *key, *value;
        char buf[8192], *ptr;
        unsigned int line = 0;
        int first_directive = 1;
        pcre_rule_t *rule = NULL;
        
        while ( prelude_read_multiline(fd, &line, buf, sizeof(buf)) == 0 ) {                
                ptr = buf + strlen(buf);
                
                /*
                 * filter space and tab at the begining of the line.
                 */
                for ( ptr = buf; (*ptr == ' ' || *ptr == '\t') && *ptr != '\0'; ptr++ );

                /*
                 * empty line or comment. 
                 */
                if ( *ptr == '\0' || *ptr == '#' )
                        continue;
                
                ret = parse_key_and_value(buf, &key, &value);                
                if ( ret < 0 )
                        continue;
                
                if ( first_directive && strcmp(key, "include") == 0 ) {
                        parse_include(NULL, plugin, value);
                        continue;
                }
                
                if ( strcmp(key, "pattern") == 0 ) {
                        if ( rule )
                                add_rule(plugin, rule);

                        rule = create_rule();
                        if ( ! rule )
                                return -1;
                        
                        first_directive = 0;
                }
                        
                if ( ! rule ) {
                        prelude_log(PRELUDE_LOG_WARN, "%s:%d: rule should start with the 'pattern' keyword.\n",
                                    filename, line);
                        continue;
                }
                
                ret = parse_rule_keyword(plugin, rule, filename, line, key, value);
                if ( ret < 0 ) {
                        free_rule(rule);
                        rule = NULL;
                        first_directive = 1;
                }
        }

        if ( rule )
                add_rule(plugin, rule);
        
        return 0;
}



static void pcre_run(prelude_plugin_instance_t *pi, idmef_message_t *idmef)
{
        int ret;
        prelude_list_t *tmp;
        pcre_plugin_t *plugin;
        pcre_rule_container_t *rc;
        pcre_match_flags_t flags, all_flags = 0;
        
        plugin = prelude_plugin_instance_get_plugin_data(pi);

        prelude_list_for_each(&plugin->rule_list, tmp) {
                rc = prelude_list_entry(tmp, pcre_rule_container_t, list);

                flags = 0;
                ret = rule_regex_match(plugin, rc, idmef, &flags);
                all_flags |= flags;
                
                if ( ret == 0 && (rc->rule->flags & PCRE_RULE_FLAGS_LAST || flags & PCRE_MATCH_FLAGS_LAST) )
                        break;
        }

#if 0
        if ( !(all_flags & PCRE_MATCH_FLAGS_ALERT) && plugin->dump_unmatched )
                prelude_log(PRELUDE_LOG_WARN, "No alert emited for log entry \"%s\"\n", lml_log_entry_get_message(log_entry));
#endif
}




static int set_last_first(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        pcre_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(context);
        
        plugin->last_rules_first = TRUE;
        
        return 0;
}


static int set_dump_unmatched(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        pcre_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(context);
        
        plugin->dump_unmatched = TRUE;
        
        return 0;
}


static void remove_top_chained(void)
{
        prelude_list_t *tmp, *bkp;
        pcre_rule_container_t *rc;
        
        prelude_list_for_each_safe(&chained_rule_list, tmp, bkp) {
                rc = prelude_list_entry(tmp, pcre_rule_container_t, list);

                if ( rc->rule->flags & PCRE_RULE_FLAGS_CHAINED )
                        free_rule_container(rc);
        }
}



static int set_pcre_ruleset(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context) 
{
        int ret;
        FILE *fd;
        char *ptr;
        pcre_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(context);
        
        plugin->rulesetdir = strdup(optarg);

        ptr = strrchr(plugin->rulesetdir, '/');
        if ( ptr )
                *ptr = '\0';
        else {
                free(plugin->rulesetdir);
                plugin->rulesetdir = NULL;
        }
        
        fd = fopen(optarg, "r");
        if ( ! fd ) {
                prelude_string_sprintf(err, "couldn't open %s for reading: %s", optarg, strerror(errno));
                return -1;
        }

        ret = parse_ruleset(&plugin->rule_list, plugin, optarg, fd);
                
        fclose(fd);
        if ( plugin->rulesetdir )
                free(plugin->rulesetdir);
        
        if ( ret < 0 )
                return -1;

        prelude_log(PRELUDE_LOG_INFO, "- pcre plugin added %d rules.\n", plugin->rulesnum);

        remove_top_chained();
        
        return 0;
}



static int pcre_activate(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        pcre_plugin_t *new;
        
        new = calloc(1, sizeof(*new));
        if ( ! new )
                return prelude_error_from_errno(errno);

        prelude_list_init(&new->rule_list);
        prelude_list_init(&new->context_list);
        
        prelude_plugin_instance_set_plugin_data(context, new);
        
        return 0;
}




static void pcre_destroy(prelude_plugin_instance_t *pi, prelude_string_t *err)
{
        prelude_list_t *tmp, *bkp;
        pcre_rule_container_t *rule;
        pcre_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(pi);
        
        prelude_list_for_each_safe(&plugin->rule_list, tmp, bkp) {
                rule = prelude_list_entry(tmp, pcre_rule_container_t, list);
                free_rule_container(rule);
        }
        
        free(plugin);
}


static void _pcre_context_destroy(pcre_context_t *ctx)
{        
        prelude_log_debug(1, "[%s]: destroying context.\n", ctx->name);
        
        if ( ctx->idmef )
                idmef_message_destroy(ctx->idmef);
        
        prelude_timer_destroy(&ctx->timer);
        prelude_list_del(&ctx->list);

        free(ctx->name);
        free(ctx);
}



void pcre_context_destroy(pcre_context_t *ctx)
{
        if ( ctx->setting->flags & PCRE_CONTEXT_SETTING_FLAGS_ALERT_ON_DESTROY && ctx->idmef ) {
                prelude_log_debug(1, "[%s]: emit alert on destroy.\n", ctx->name);
                correlation_alert_emit(ctx->idmef);
        }
        
        _pcre_context_destroy(ctx);
}



static void pcre_context_expire(void *data)
{
        pcre_context_t *ctx = data;
        
        if ( ctx->setting->flags & PCRE_CONTEXT_SETTING_FLAGS_ALERT_ON_EXPIRE && ctx->idmef ) {
                prelude_log_debug(1, "[%s]: emit alert on expire.\n", ctx->name);
                correlation_alert_emit(ctx->idmef);
        }
        
        _pcre_context_destroy(ctx);
}



idmef_message_t *pcre_context_get_idmef(pcre_context_t *ctx)
{
        return ctx->idmef;
}



int pcre_context_check_correlation(pcre_context_t *ctx)
{
        pcre_context_setting_t *setting = ctx->setting;
        
        if ( ! setting )
                return 0;

        prelude_log_debug(1, "[%s]: correlation check threshold=%d required=%d.\n",
                          ctx->name, ctx->threshold + 1, setting->correlation_threshold);
        
        if ( setting->correlation_threshold && ++ctx->threshold != setting->correlation_threshold )
                return -1;

        return 0;
}



int pcre_context_new(pcre_context_t **out, pcre_plugin_t *plugin,
                     const char *name, idmef_message_t *idmef, pcre_context_setting_t *setting)
{
        pcre_context_t *ctx;

        if ( ! (setting->flags & PCRE_CONTEXT_SETTING_FLAGS_QUEUE) ) {
                ctx = pcre_context_search(plugin, name);
                if ( ctx ) {
                        if ( setting->flags & PCRE_CONTEXT_SETTING_FLAGS_OVERWRITE ) {
                                prelude_log_debug(1, "[%s]: destroying on create (overwrite).\n", name);
                                pcre_context_destroy(ctx);
                        } else {
                                prelude_log_debug(1, "[%s]: already exist, create only specified.\n", name);
                                return -2;
                        }
                }
        }
        
        *out = ctx = calloc(1, sizeof(*ctx));
        if ( ! ctx ) {
                prelude_log(PRELUDE_LOG_ERR, "memory exhausted.\n");
                return -1;
        }

        prelude_log_debug(1, "[%s]: creating context (expire=%ds cthresh=%d).\n", name, setting->timeout,
                          setting->correlation_threshold);
        
        ctx->name = strdup(name);
        if ( ! ctx->name ) {
                free(ctx);
                prelude_log(PRELUDE_LOG_ERR, "memory exhausted.\n");
                return -1;
        }

        ctx->setting = setting;
        prelude_timer_init_list(&ctx->timer);
                
        if ( setting->timeout > 0 ) {
                prelude_timer_set_data(&ctx->timer, ctx);
                prelude_timer_set_expire(&ctx->timer, setting->timeout);
                prelude_timer_set_callback(&ctx->timer, pcre_context_expire);
                prelude_timer_init(&ctx->timer);
        }

        if ( idmef )
                ctx->idmef = idmef_message_ref(idmef);
        
        prelude_list_add_tail(&plugin->context_list, &ctx->list);
        
        return 0;
}



pcre_context_t *pcre_context_search(pcre_plugin_t *plugin, const char *name)
{
        pcre_context_t *ctx;
        prelude_list_t *tmp;

        prelude_list_for_each(&plugin->context_list, tmp) {
                ctx = prelude_list_entry(tmp, pcre_context_t, list);

                if ( strcmp(ctx->name, name) == 0 )
                        return ctx;
        }
        
        return NULL;
}



int pcre_LTX_correlation_plugin_init(prelude_plugin_entry_t *pe, void *root_optlist)
{
        int ret;
        prelude_option_t *opt, *popt;
        int hook = PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG;
        
        ret = prelude_option_add(root_optlist, &opt, hook, 0, "pcre", "Pcre plugin option",
                                 PRELUDE_OPTION_ARGUMENT_OPTIONAL, pcre_activate, NULL);
        if ( ret < 0 )
                return ret;
        
        prelude_plugin_set_activation_option(pe, opt, NULL);
        
        ret = prelude_option_add(opt, NULL, hook, 'r', "ruleset", "Ruleset to use",
                                 PRELUDE_OPTION_ARGUMENT_REQUIRED, set_pcre_ruleset, NULL);
        if ( ret < 0 )
                return ret;
        
        ret = prelude_option_add(opt, &popt, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG, 'l',
                                 "last-first", "Process rules with the \"last\" attribute first",
                                 PRELUDE_OPTION_ARGUMENT_NONE, set_last_first, NULL);
        if ( ret < 0 )
                return ret;
        prelude_option_set_priority(popt, PRELUDE_OPTION_PRIORITY_FIRST);

        ret = prelude_option_add(opt, &popt, PRELUDE_OPTION_TYPE_CLI, 0,
                                 "dump-unmatched", "Dump unmatched log entry",
                                 PRELUDE_OPTION_ARGUMENT_NONE, set_dump_unmatched, NULL);
        if ( ret < 0 )
                return ret;

        pcre_plugin.run = pcre_run;
        prelude_plugin_set_name(&pcre_plugin, "pcre");
        prelude_plugin_set_destroy_func(&pcre_plugin, pcre_destroy);
        
        prelude_plugin_entry_set_plugin(pe, (void *) &pcre_plugin);
        
        return 0;
}



int pcre_LTX_prelude_plugin_version(void)
{
        return PRELUDE_PLUGIN_API_VERSION;
}
