# Copyright (C) 2009-2018 CS-SI. All Rights Reserved.
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
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

import re
import time
from preludecorrelator import context
from preludecorrelator.pluginmanager import Plugin


def _evict(ctx):
    now = time.time()
    for target, values in ctx._protected_hosts.items():
        if now - values[0] > ctx._flush_protected_hosts:
            ctx._protected_hosts.pop(target)

    ctx.reset()


def _alert(ctx):
    cnt = 0
    fw = context.search("FIREWALL INFOS")

    for idmef in ctx.candidates:
        source = idmef.get("alert.source(0).node.address(0).address")
        target = idmef.get("alert.target(0).node.address(0).address")
        dport = str(idmef.get("alert.target(0).service.port", 0))

        if target not in fw._protected_hosts:
            continue

        if (source + dport) in fw._protected_hosts[target][1]:
            continue

        cnt += 1
        ctx.addAlertReference(idmef)

    if cnt > 0:
        ctx.set("alert.classification.text", "Events hit target")
        ctx.set("alert.assessment.impact.severity", "medium")
        ctx.set("alert.assessment.impact.description",
                "The target are known to be protected by a Firewall device, but a set of event have not been dropped")
        ctx.set("alert.correlation_alert.name", "No firewall block observed")
        ctx.alert()

    ctx.destroy()


class FirewallPlugin(Plugin):
    def __init__(self, env):
        Plugin.__init__(self, env)
        self._flush_protected_hosts = self.getConfigValue("flush-protected-hosts", 3600, type=int)

    def run(self, idmef):
        source = idmef.get("alert.source(0).node.address(0).address")
        scat = idmef.get("alert.source(0).node.address(0).category")
        target = idmef.get("alert.target(0).node.address(0).address")
        tcat = idmef.get("alert.target(0).node.address(0).category")

        dport = idmef.get("alert.target(0).service.port")
        if not source or not target or not dport:
            return

        if scat not in ("ipv4-addr", "ipv6-addr") or tcat not in ("ipv4-addr", "ipv6-addr"):
            return

        ctx = context.Context("FIREWALL INFOS",
                              {"expire": self._flush_protected_hosts, "alert_on_expire": _evict},
                              update=True, ruleid=self.name)
        if ctx.getUpdateCount() == 0:
            ctx._protected_hosts = {}
            ctx._flush_protected_hosts = self._flush_protected_hosts

        if idmef.match("alert.classification.text", re.compile("[Pp]acket [Dd]ropped|[Dd]enied")):
            if target not in ctx._protected_hosts:
                ctx._protected_hosts[target] = [0, {}]

            ctx._protected_hosts[target][0] = float(idmef.getTime())
            ctx._protected_hosts[target][1][source + str(dport)] = True
        else:
            if target not in ctx._protected_hosts:
                return

            if time.time() - ctx._protected_hosts[target][0] > self._flush_protected_hosts:
                ctx._protected_hosts.pop(target)
                return

            if (source + str(dport)) in ctx._protected_hosts[target][1]:
                return

            ctx = context.Context(("FIREWALL", source), {"expire": 120, "alert_on_expire": _alert},
                                  update=True, ruleid=self.name)
            if ctx.getUpdateCount() == 0:
                ctx.candidates = []

            ctx.candidates.append(idmef)
