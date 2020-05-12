# VERSION: 1.0
# AUTHOR: Prelude Team <support.prelude@c-s.fr>
# DESCRIPTION: Triggered when the source IP is present in the CIArmy reputation database
# Copyright (C) 2015-2020 CS-SI. All Rights Reserved.
# Author: Thomas Andrejak <thomas.andrejak@c-s.fr>
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

from preludecorrelator import context, require, log, download
from preludecorrelator.pluginmanager import Plugin

logger = log.getLogger(__name__)


class CIArmyDownloader(download.HTTPDownloadCache):
    def __init__(self, filename, uri, timeout, reload):
        download.HTTPDownloadCache.__init__(self, "CIArmy", filename, uri, timeout, reload, logger)

    def __ipNormalize(self, ip):
        return ".".join([i.lstrip("0") for i in ip.split(".")])

    def parse(self, data):
        ret = []

        for line in data.split("\n"):
            if not line or line[0] == '#':
                continue

            ip = line
            ret.append(self.__ipNormalize(ip))

        return ret


class CIArmyPlugin(Plugin):
    CIARMY_RELOAD = 7 * 24 * 60 * 60
    CIARMY_URI = "http://cinsscore.com/list/ci-badguys.txt"
    CIARMY_TIMEOUT = 10

    def __init__(self, env):
        Plugin.__init__(self, env)

        uri = self.getConfigValue("uri", self.CIARMY_URI)
        timeout = self.getConfigValue("timeout", self.CIARMY_TIMEOUT, type=float)
        reload = self.getConfigValue("reload", self.CIARMY_RELOAD, type=int)
        filename = self.getConfigValue("filename",
                                       require.get_data_filename("ciarmy.dat", module=__name__, profile=env.profile))

        self.__data = CIArmyDownloader(filename, uri, timeout, reload)

    def run(self, idmef):
        data = self.__data.get()

        for source in idmef.get("alert.source(*).node.address(*).address"):
            if source in data:
                ca = context.Context(("CIARMY", source), {"expire": 20, "alert_on_expire": True}, update=True,
                                     idmef=idmef, ruleid=self.name)
                if ca.getUpdateCount() == 0:
                    ca.set("alert.classification.text", "IP source matching CIArmy database")
                    ca.set("alert.correlation_alert.name", "IP source matching CIArmy database")
                    ca.set("alert.assessment.impact.description",
                           "CIArmy gathered this IP address from firewall drop logs (%s)" % source)
                    ca.set("alert.assessment.impact.severity", "high")
