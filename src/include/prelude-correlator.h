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

#ifndef _PRELUDE_CORRELATOR_H
#define _PRELUDE_CORRELATOR_H

#include <libprelude/prelude.h>

typedef struct {
        PRELUDE_PLUGIN_GENERIC;
        void (*run)(prelude_plugin_instance_t *pi, idmef_message_t *idmef);
        void (*got_signal)(prelude_plugin_instance_t *pi, int signo);
} prelude_correlator_plugin_t;

void correlation_plugin_set_signal_func(prelude_correlator_plugin_t *plugin, void (*cb)(prelude_plugin_instance_t *pi, int signo));

void correlation_plugin_register_signal(prelude_correlator_plugin_t *plugin, int signo);

void correlation_alert_emit(idmef_message_t *idmef);

#endif
