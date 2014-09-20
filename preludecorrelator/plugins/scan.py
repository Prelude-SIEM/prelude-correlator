# Copyright (C) 2006 G Ramon Gomez <gene at gomezbrothers dot com>
# Copyright (C) 2009-2012 CS-SI <info@prelude-ids.com>
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

class EventScanPlugin(Plugin):
    def run(self, idmef):
        source = idmef.get("alert.source(*).node.address(*).address")
        target = idmef.get("alert.target(*).node.address(*).address")

        if not source or not target:
            return

        for saddr in source:
            for daddr in target:
                ctx = Context(("SCAN EVENTSCAN", saddr, daddr), { "expire": 60, "threshold": 30, "alert_on_expire": True }, update = True, idmef=idmef)
                if ctx.getUpdateCount() == 0:
                    ctx.set("alert.correlation_alert.name", "A single host has played many events against a single target. This may be a vulnerability scan")
                    ctx.set("alert.classification.text", "Eventscan")
                    ctx.set("alert.assessment.impact.severity", "high")


# Detect Eventsweep:
# Playing the same event from a single host against multiple hosts
class EventSweepPlugin(Plugin):
    def run(self, idmef):
        classification = idmef.get("alert.classification.text")
        source = idmef.get("alert.source(*).node.address(*).address")
        target = idmef.get("alert.target(*).node.address(*).address")

        if not source or not target or not classification:
            return

        for saddr in source:
            ctx = Context(("SCAN EVENTSWEEP", classification, saddr), { "expire": 60, "threshold": 30, "alert_on_expire": True }, overwrite = False)
            if ctx.getUpdateCount() == 0:
                ctx.set("alert.correlation_alert.name", "A single host has played the same event against multiple targets. This may be a network scan for a specific vulnerability")
                ctx.set("alert.classification.text", "Eventsweep")
                ctx.set("alert.assessment.impact.severity", "high")

            cur = ctx.get("alert.target(*).node.address(*).address")
            if cur:
                for address in target:
                    if address in cur:
                        insert = False
                        return

            ctx.update(idmef=idmef, timer_rst=ctx.getUpdateCount())


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

