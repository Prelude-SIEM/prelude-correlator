# Copyright (C) 2009 PreludeIDS Technologies. All Rights Reserved.
# Author: Yoann Vandoorselaere <yoann.v@prelude-ids.com>
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

import re
from PreludeCorrelator import context
from PreludeCorrelator.pluginmanager import Plugin

class FirewallPlugin(Plugin):
    def run(self, idmef):
        source = idmef.Get("alert.source(0).node.address(0).address")
        target = idmef.Get("alert.target(0).node.address(0).address")
        dport = idmef.Get("alert.target(0).service.port", 0)

        if not source or not target:
                return

        ctxname = "FIREWALL_" + source + target + str(dport)

        if idmef.match("alert.classification.text", re.compile("[Pp]acket [Dd]ropped|[Dd]enied")):
                # overwrite any existing context, with the same name.
                ctx = context.Context(ctxname, { "expire": 10 }, update=True)
                ctx.block_installed = True
        else:
                # Begins a timer for every event that contains a source and a target
                # address which has not been matched by an observed packet denial.  If a packet
                # denial is not observed in the next 10 seconds, an event alert is generated.
                ctx = context.search(ctxname)
                if not ctx or ctx.block_installed == False:
                        ctx = context.Context(ctxname, { "expire": 10, "alert_on_expire": True }, idmef=idmef, update=True)
                        ctx.Set("alert.assessment", idmef.Get("alert.assessment"))
                        ctx.Set("alert.classification", idmef.Get("alert.classification"))
                        ctx.Set("alert.correlation_alert.name", "No firewall block observed for these events")
                        ctx.block_installed = False
