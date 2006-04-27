#ifndef _PRELUDE_CORRELATOR_H
#define _PRELUDE_CORRELATOR_H

#include <libprelude/prelude.h>

typedef struct {
        PRELUDE_PLUGIN_GENERIC;
        void (*run)(prelude_plugin_instance_t *pi, idmef_message_t *idmef);
} prelude_correlator_plugin_t;


void correlation_alert_emit(idmef_message_t *idmef);

#endif
