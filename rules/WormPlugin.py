# VERSION: 1.0
# AUTHOR: Prelude Team <support.prelude@csgroup.eu>
# DESCRIPTION: Triggered by a host becoming the source of many alerts after having been the target of similar alerts
# Copyright (C) 2006 G Ramon Gomez <gene at gomezbrothers dot com>
# Copyright (C) 2009-2020 CS GROUP - France <support.prelude@csgroup.eu>
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
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

# This rule looks for events against a host, records the messageid, then sets
# a timer of 600 seconds.   If the host then replays the event against
# other hosts multiple times, an event is generated.

from preludecorrelator import context
from preludecorrelator.pluginmanager import Plugin


class WormPlugin(Plugin):
    REPEAT = 5

    def __init__(self, env):
        Plugin.__init__(self, env)
        self.__repeat_target = self.getConfigValue("repeat-target", self.REPEAT, type=int)

    def run(self, idmef):
        ctxt = idmef.get("alert.classification.text")
        if not ctxt:
            return

        # Create context for classification combined with all the target.
        tlist = {}
        for target in idmef.get("alert.target(*).node.address(*).address"):
            ctx = context.Context(("WORM HOST", ctxt, target), {"expire": 300},
                                  overwrite=False, idmef=idmef, ruleid=self.name)
            if ctx.getUpdateCount() == 0:
                ctx._target_list = {}

            tlist[target] = True

        for source in idmef.get("alert.source(*).node.address(*).address"):
            # We are trying to see whether a previous target is now attacking other hosts
            # thus, we check whether a context exist with this classification combined to
            # this source.
            ctx = context.search(("WORM HOST", ctxt, source))
            if not ctx:
                continue

            plen = len(ctx._target_list)
            ctx._target_list.update(tlist)

            nlen = len(ctx._target_list)
            if nlen > plen:
                ctx.update(idmef=idmef)

            if nlen >= self.__repeat_target:
                ctx.set("alert.classification.text", "Possible Worm Activity")
                ctx.set("alert.correlation_alert.name", "Source host is repeating actions taken against it recently")
                ctx.set("alert.assessment.impact.severity", "high")
                ctx.set("alert.assessment.impact.description",
                        source + " has repeated actions taken against it recently at least %d times. It may have been "
                                 "infected with a worm." % self.__repeat_target)
                ctx.alert()
                ctx.destroy()
