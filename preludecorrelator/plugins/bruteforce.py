# Copyright (C) 2006 G Ramon Gomez <gene at gomezbrothers dot com>
# Copyright (C) 2009-2015 CS-SI <support.prelude@c-s.fr>
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
from preludecorrelator.pluginmanager import Plugin
from preludecorrelator.context import Context

class BruteForcePlugin(Plugin):
    def _BruteForce(self, idmef):
        sadd = idmef.get("alert.source(*).node.address(*).address")
        tadd = idmef.get("alert.target(*).node.address(*).address")
        if not sadd or not tadd:
            return

        for source in sadd:
            for target in tadd:
                ctx = Context(("BRUTE ST", source, target), { "expire": 120, "threshold": 5, "alert_on_expire": True }, update=True, idmef = idmef)
                if ctx.getUpdateCount() == 0:
                    ctx.set("alert.classification.text", "Brute Force attack")
                    ctx.set("alert.correlation_alert.name", "Multiple failed login")
                    ctx.set("alert.assessment.impact.severity", "high")
                    ctx.set("alert.assessment.impact.description", "Multiple failed attempts have been made to login using different account")

    def _BruteUserForce(self, idmef):
        userid = idmef.get("alert.target(*).user.user_id(*).name");
        if not userid:
            return

        for user in userid:
            ctx = Context(("BRUTE USER", user), { "expire": 120, "threshold": 5, "alert_on_expire": True }, update=True, idmef=idmef)
            if ctx.getUpdateCount() == 0:
                ctx.set("alert.classification.text", "Brute Force attack")
                ctx.set("alert.correlation_alert.name", "Multiple failed login against a single account")
                ctx.set("alert.assessment.impact.severity", "high")
                ctx.set("alert.assessment.impact.description", "Multiple failed attempts have been made to login to a user account")


    def run(self, idmef):
        if not idmef.match("alert.classification.text", re.compile("[Ll]ogin|[Aa]uthentication")):
            return

        # FIXME: In the future, we might want to include successfull authentication
        # following a number of failed events, so that generated CorrelationAlert
        # includes full details.
        if idmef.get("alert.assessment.impact.completion") == "succeeded":
            return

        self._BruteForce(idmef)
        self._BruteUserForce(idmef)
