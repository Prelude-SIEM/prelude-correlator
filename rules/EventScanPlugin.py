# Copyright (C) 2006 G Ramon Gomez <gene at gomezbrothers dot com>
# Copyright (C) 2009-2018 CS-SI <support.prelude@c-s.fr>
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
                ctx = Context(("SCAN EVENTSCAN", saddr, daddr),
                              {"expire": 60, "threshold": 30, "alert_on_expire": True},
                              update=True, idmef=idmef, ruleid=self.name)
                if ctx.getUpdateCount() == 0:
                    ctx.set("alert.correlation_alert.name",
                            "A single host has played many events against a single target. This may be a vulnerability "
                            "scan")
                    ctx.set("alert.classification.text", "Eventscan")
                    ctx.set("alert.assessment.impact.severity", "high")
