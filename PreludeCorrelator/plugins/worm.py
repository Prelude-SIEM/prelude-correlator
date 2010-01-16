# Copyright (C) 2006 G Ramon Gomez <gene at gomezbrothers dot com>
# Copyright (C) 2009 PreludeIDS Technologies <yoann.v@prelude-ids.com>
# All Rights Reserved.
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

# This rule looks for events against a host, records the messageid, then sets
# a timer of 600 seconds.   If the host then replays the event against
# other hosts multiple times, an event is generated.

from PreludeCorrelator import context
from PreludeCorrelator.pluginmanager import Plugin

class WormPlugin(Plugin):
    REPEAT = 5

    def __init__(self, env):
        Plugin.__init__(self, env)
        self.__repeat_target = self.getConfigValue("repeat-target", self.REPEAT, type=int)

    def run(self, idmef):
        ctxt = idmef.Get("alert.classification.text")
        if not ctxt:
            return

        # Create context for classification combined with all the target.
        tlist = {}
        for target in idmef.Get("alert.target(*).node.address(*).address"):
            ctx = context.Context("WORM_HOST_" + ctxt + target, { "expire": 300 }, overwrite=False, idmef=idmef)
            if ctx.getUpdateCount() == 0:
                ctx._target_list = {}

            tlist[target] = True

        for source in idmef.Get("alert.source(*).node.address(*).address"):
            # We are trying to see whether a previous target is now attacking other hosts
            # thus, we check whether a context exist with this classification combined to
            # this source.
            ctx = context.search("WORM_HOST_" + ctxt + source)
            if not ctx:
                continue

            plen = len(ctx._target_list)
            ctx._target_list.update(tlist)

            nlen = len(ctx._target_list)
            if nlen > plen:
                ctx.update(idmef=idmef)

            if nlen >= self.__repeat_target:
                ctx.Set("alert.classification.text", "Possible Worm Activity")
                ctx.Set("alert.correlation_alert.name", "Source host is repeating actions taken against it recently")
                ctx.Set("alert.assessment.impact.severity", "high")
                ctx.Set("alert.assessment.impact.description", source + " has repeated actions taken against it recently at least 5 times. It may have been infected with a worm.")
                ctx.alert()
                ctx.destroy()
