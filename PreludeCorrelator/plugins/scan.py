# Copyright (C) 2006 G Ramon Gomez <gene at gomezbrothers dot com>
# Copyright (C) 2009 PreludeIDS Technologies <info@prelude-ids.com>
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
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING.  If not, write to
# the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.

# Detect Eventscan:
# Playing multiple events from a single host against another single host

from PreludeCorrelator.context import Context
from PreludeCorrelator.pluginmanager import Plugin

class EventScanPlugin(Plugin):
    def run(self, idmef):
        source = idmef.Get("alert.source(*).node.address(*).address")
        target = idmef.Get("alert.target(*).node.address(*).address")

        if not source or not target:
            return

        for saddr in source:
            for daddr in target:
                ctx = Context("SCAN_EVENTSCAN_" + saddr + daddr, { "expire": 60, "threshold": 30, "alert_on_expire": True }, update = True, idmef=idmef)
                if ctx.getUpdateCount() == 0:
                    ctx.Set("alert.correlation_alert.name", "A single host has played many events against a single target. This may be a vulnerability scan")
                    ctx.Set("alert.classification.text", "Eventscan")
                    ctx.Set("alert.assessment.impact.severity", "high")


# Detect Eventsweep:
# Playing the same event from a single host against multiple hosts
class EventSweepPlugin(Plugin):
    def run(self, idmef):
        classification = idmef.Get("alert.classification.text")
        source = idmef.Get("alert.source(*).node.address(*).address")
        target = idmef.Get("alert.target(*).node.address(*).address")

        if not source or not target or not classification:
            return

        for saddr in source:
            ctx = Context("SCAN_EVENTSWEEP_" + classification + saddr, { "expire": 60, "threshold": 30, "alert_on_expire": True }, overwrite = False)
            if ctx.getUpdateCount() == 0:
                ctx.Set("alert.correlation_alert.name", "A single host has played the same event against multiple targets. This may be a network scan for a specific vulnerability")
                ctx.Set("alert.classification.text", "Eventsweep")
                ctx.Set("alert.assessment.impact.severity", "high")

            cur = ctx.Get("alert.target(*).node.address(*).address")
            if cur:
                for address in target:
                    if address in cur:
                        insert = False
                        return

            ctx.update(idmef=idmef)


# Detect Eventstorm:
# Playing excessive events by a single host
class EventStormPlugin(Plugin):
    def run(self, idmef):
        source = idmef.Get("alert.source(*).node.address(*).address")
        if not source:
            return

        for saddr in source:
            ctx = Context("SCAN_EVENTSTORM_" + saddr, { "expire": 120, "threshold": 150, "alert_on_expire": True }, update = True, idmef = idmef)
            if ctx.getUpdateCount() == 0:
                ctx.Set("alert.correlation_alert.name", "A single host is producing an unusual amount of events")
                ctx.Set("alert.classification.text", "Eventstorm")
                ctx.Set("alert.assessment.impact.severity", "high")

