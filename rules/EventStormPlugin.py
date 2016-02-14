# Copyright (C) 2006 G Ramon Gomez <gene at gomezbrothers dot com>
# Copyright (C) 2009-2016 CS-SI <support.prelude@c-s.fr>
#
# This file is part of the Prelude-Correlator program.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

# Detect Eventscan:
# Playing multiple events from a single host against another single host

from preludecorrelator.context import Context
from preludecorrelator.pluginmanager import Plugin

# Detect Eventstorm:
# Playing excessive events by a single host
class EventStormPlugin(Plugin):
    def run(self, idmef):
        source = idmef.get("alert.source(*).node.address(*).address")
        if not source:
            return

        for saddr in source:
            ctx = Context(("SCAN EVENTSTORM", saddr), { "expire": 120, "threshold": 150, "alert_on_expire": True }, update = True, idmef = idmef)
            if ctx.getUpdateCount() == 0:
                ctx.set("alert.correlation_alert.name", "A single host is producing an unusual amount of events")
                ctx.set("alert.classification.text", "Eventstorm")
                ctx.set("alert.assessment.impact.severity", "high")

