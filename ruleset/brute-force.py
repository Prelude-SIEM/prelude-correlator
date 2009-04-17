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

import re
from pycor.plugins import Plugin
from pycor.context import Context

class BrutePlugin(Plugin):
    def _BruteForce(self, idmef):
        sadd = idmef.Get("alert.source(*).node.address(*).address")
        tadd = idmef.Get("alert.target(*).node.address(*).address")
        if not sadd or not tadd:
            return

        for source in sadd:
            for target in tadd:
                ctx = Context("BRUTE_ST_" + source + target, { "expire": 2, "threshold": 5 }, update = True)
                ctx.Set("alert.source(>>)", idmef.Get("alert.source"))
                ctx.Set("alert.target(>>)", idmef.Get("alert.target"))
                ctx.Set("alert.correlation_alert.alertident(>>).alertident", idmef.Get("alert.messageid"))
                ctx.Set("alert.correlation_alert.alertident(-1).analyzerid", idmef.Get("alert.analyzer(*).analyzerid")[-1])

                if ctx.CheckAndDecThreshold():
                    ctx.Set("alert.classification.text", "Brute force attack")
                    ctx.Set("alert.correlation_alert.name", "Multiple failed login")
                    ctx.Set("alert.assessment.impact.severity", "high")
                    ctx.Set("alert.assessment.impact.description", "Multiple failed attempts have been made to login to a user account")
                    ctx.alert()
                    ctx.destroy()

    def _BruteUserForce(self, idmef):
        userid = idmef.Get("alert.target(*).user.user_id(*).name");
        if not userid:
            return

        for user in userid:
            ctx = Context("BRUTE_U_" + user, { "expire": 120, "threshold": 2 }, update = True)
            ctx.Set("alert.source(>>)", idmef.Get("alert.source"))
            ctx.Set("alert.target(>>)", idmef.Get("alert.target"))
            ctx.Set("alert.correlation_alert.alertident(>>).alertident", idmef.Get("alert.messageid"))
            ctx.Set("alert.correlation_alert.alertident(-1).analyzerid", idmef.Get("alert.analyzer(*).analyzerid")[-1])

            if ctx.CheckAndDecThreshold():
                ctx.Set("alert.classification.text", "Brute force attack")
                ctx.Set("alert.correlation_alert.name", "Multiple failed login")
                ctx.Set("alert.assessment.impact.severity", "high")
                ctx.Set("alert.assessment.impact.description", "Multiple failed attempts have been made to login to a user account")
                ctx.alert()
                ctx.destroy()


    def run(self, idmef):
        if not idmef.match("alert.classification.text", re.compile("[Ll]ogin|[Aa]uthentication"),
                           "alert.assessment.impact.completion", "failed"):
            return

        self._BruteForce()
        self._BruteUserForce()
