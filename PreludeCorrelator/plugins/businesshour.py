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

import time
from PreludeCorrelator.idmef import IDMEF
from PreludeCorrelator.pluginmanager import Plugin

# Alert only on saturday and sunday, and everyday from 6:00pm to 9:00am.

class BusinessHourPlugin(Plugin):
    def run(self, idmef):

        t = time.localtime(int(idmef.Get("alert.create_time")))

        if not (t.tm_wday == 5 or t.tm_wday == 6 or t.tm_hour < 9 or t.tm_hour > 17):
                return

        if idmef.Get("alert.assessment.impact.completion") != "succeeded":
                return

        ca = IDMEF()
        ca.Set("alert.source", idmef.Get("alert.source"))
        ca.Set("alert.target", idmef.Get("alert.target"))
        ca.Set("alert.classification", idmef.Get("alert.classification"))
        ca.Set("alert.correlation_alert.alertident(>>).alertident", idmef.Get("alert.messageid"))
        ca.Set("alert.correlation_alert.alertident(-1).analyzerid", idmef.Get("alert.analyzer(*).analyzerid")[-1])
        ca.Set("alert.correlation_alert.name", "Critical system activity on day off")
        ca.alert()
