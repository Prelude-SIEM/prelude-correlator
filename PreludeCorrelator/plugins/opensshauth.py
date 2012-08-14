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

from PreludeCorrelator.pluginmanager import Plugin
from PreludeCorrelator.context import Context

def alert(ctx):
    if len(ctx.authtype) > 1:
        ctx.Set("alert.classification.text", "Multiple authentication methods")
        ctx.Set("alert.correlation_alert.name", "Multiple authentication methods")
        ctx.Set("alert.assessment.impact.severity", "medium")
        ctx.Set("alert.assessment.impact.description", "Multiple ways of authenticating a single user have been found over SSH. If passphrase is the only allowed method, make sure you disable passwords.")
        ctx.alert()
    ctx.destroy()

class OpenSSHAuthPlugin(Plugin):
    def run(self, idmef):
        if idmef.Get("alert.analyzer(-1).manufacturer") != "OpenSSH":
                return

        if idmef.Get("alert.assessment.impact.completion") != "succeeded":
                return

        try:
                idx = idmef.Get("alert.additional_data(*).meaning").index("Authentication method")
        except:
                return

        data = idmef.Get("alert.additional_data(%d).data" % idx)

        for username in idmef.Get("alert.target(*).user.user_id(*).name"):
            for target in idmef.Get("alert.target(*).node.address(*).address"):
                ctx = Context(("SSHAUTH", target, username), { "expire": 30, "alert_on_expire": alert }, update=True)
                if ctx.getUpdateCount() == 0:
                    ctx.authtype = { data: True }
                    ctx.addAlertReference(idmef)

                elif not ctx.authtype.has_key(data):
                    ctx.authtype[data] = True
                    ctx.addAlertReference(idmef)
