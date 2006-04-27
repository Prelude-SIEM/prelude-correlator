#include <libprelude/prelude.h>
#include <libprelude/prelude-log.h>
#include <libprelude/prelude-plugin.h>

#include "prelude-correlator.h"
#include "correlation-plugins.h"

#define CORRELATION_PLUGIN_SYMBOL "correlation_plugin_init"


static PRELUDE_LIST(correlation_plugins_instance);



static int subscribe(prelude_plugin_instance_t *pi)
{
        prelude_plugin_generic_t *plugin = prelude_plugin_instance_get_plugin(pi);
        
        prelude_log(PRELUDE_LOG_INFO, "- Subscribing plugin %s[%s]\n",
                    plugin->name, prelude_plugin_instance_get_name(pi));

        prelude_linked_object_add(&correlation_plugins_instance, (prelude_linked_object_t *) pi);

        return 0;
}



static void unsubscribe(prelude_plugin_instance_t *pi)
{
        prelude_plugin_generic_t *plugin = prelude_plugin_instance_get_plugin(pi);
        
        prelude_log(PRELUDE_LOG_INFO, "- Unsubscribing plugin %s[%s]\n",
                    plugin->name, prelude_plugin_instance_get_name(pi));
        
        prelude_linked_object_del((prelude_linked_object_t *) pi);
}



void correlation_plugins_run(idmef_message_t *idmef)
{
        prelude_list_t *tmp;
        prelude_plugin_instance_t *pi;
        
        prelude_list_for_each(&correlation_plugins_instance, tmp) {
                pi = prelude_linked_object_get_object(tmp); 
                prelude_plugin_run(pi, prelude_correlator_plugin_t, run, pi, idmef);
        }
}


int correlation_plugins_init(void *data)
{
        int ret;

        ret = prelude_plugin_load_from_dir(NULL, CORRELATION_PLUGIN_DIR,
                                           CORRELATION_PLUGIN_SYMBOL, data, subscribe, unsubscribe);
        if ( ret < 0 ) {
                prelude_perror(ret, "could not load plugin subsystem");
                return -1;
        }

        if ( ret == 0 )
                prelude_log(PRELUDE_LOG_WARN, "* Warning: No correlation plugin loaded from '%s'.\n", CORRELATION_PLUGIN_DIR);
                
        return ret;
}
