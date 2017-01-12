# Copyright (C) 2009-2017 CS-SI. All Rights Reserved.
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

import time
from preludecorrelator.idmef import IDMEF
from preludecorrelator.pluginmanager import Plugin

# Alert only on saturday and sunday, and everyday from 6:00pm to 9:00am.

class BusinessHourPlugin(Plugin):
    def run(self, idmef):

        t = time.localtime(int(idmef.get("alert.create_time")))

        if not (t.tm_wday == 5 or t.tm_wday == 6 or t.tm_hour < 9 or t.tm_hour > 17):
                return

        if idmef.get("alert.assessment.impact.completion") != "succeeded":
                return

        ca = IDMEF()
        ca.addAlertReference(idmef)
        ca.set("alert.classification", idmef.get("alert.classification"))
        ca.set("alert.correlation_alert.name", "Critical system activity on day off")
        ca.alert()
