# Copyright (C) 2009-2012 CS-SI. All Rights Reserved.
# Author: Sebastien Tricaud <stricaud@inl.fr>
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

from preludecorrelator.pluginmanager import Plugin
from preludecorrelator.context import Context

def alert(ctx):
    if len(ctx.authtype) > 1:
        ctx.set("alert.classification.text", "Multiple authentication methods")
        ctx.set("alert.correlation_alert.name", "Multiple authentication methods")
        ctx.set("alert.assessment.impact.severity", "medium")
        ctx.set("alert.assessment.impact.description", "Multiple ways of authenticating a single user have been found over SSH. If passphrase is the only allowed method, make sure you disable passwords.")
        ctx.alert()
    ctx.destroy()

class OpenSSHAuthPlugin(Plugin):
    def run(self, idmef):
        if idmef.get("alert.analyzer(-1).manufacturer") != "OpenSSH":
                return

        if idmef.get("alert.assessment.impact.completion") != "succeeded":
                return

        data = idmef.get("alert.additional_data('Authentication method').data")
        if not data:
                return

        data = data[0]
        for username in idmef.get("alert.target(*).user.user_id(*).name"):
            for target in idmef.get("alert.target(*).node.address(*).address"):
                ctx = Context(("SSHAUTH", target, username), { "expire": 30, "alert_on_expire": alert }, update=True)
                if ctx.getUpdateCount() == 0:
                    ctx.authtype = { data: True }
                    ctx.addAlertReference(idmef)

                elif not data in ctx.authtype:
                    ctx.authtype[data] = True
                    ctx.addAlertReference(idmef)
