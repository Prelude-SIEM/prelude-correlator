# Copyright (C) 2009-2015 CS-SI. All Rights Reserved.
# Author: Yoann Vandoorselaere <yoann.v@prelude-ids.com>
# Author: Sebastien Tricaud <stricaud@inl.fr>
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


class DShieldDownloader(download.HTTPDownloadCache):
    def __init__(self, filename, uri, timeout, reload):
        download.HTTPDownloadCache.__init__(self, "DShield", filename, uri, timeout, reload, logger)

    def __ipNormalize(self, ip):
        return ".".join([ i.lstrip("0") for i in ip.split(".") ])

    def parse(self, data):
        ret = {}

        for line in data.split("\n"):
            if not line or line[0] == '#':
                continue

            ip, reports, attacks, first_seen, last_seen = line.split('\t')
            ret[self.__ipNormalize(ip)] = (int(reports), int(attacks), first_seen, last_seen)

        return ret


class DshieldPlugin(Plugin):
    DSHIELD_RELOAD = 7 * 24 * 60 * 60
    DSHIELD_URI = "http://www.dshield.org/ipsascii.html?limit=10000"
    DSHIELD_TIMEOUT = 10
    DSHIELD_FILENAME = require.get_data_filename("dshield.dat", module=__name__)

    def __init__(self, env):
        Plugin.__init__(self, env)

        uri = self.getConfigValue("uri", self.DSHIELD_URI)
        timeout = self.getConfigValue("timeout", self.DSHIELD_TIMEOUT, type=float)
        reload = self.getConfigValue("reload", self.DSHIELD_RELOAD, type=int)
        filename = self.getConfigValue("filename", self.DSHIELD_FILENAME)

        self.__data = DShieldDownloader(filename, uri, timeout, reload)

    def run(self, idmef):
        data = self.__data.get()

        for source in idmef.get("alert.source(*).node.address(*).address"):
            entry = data.get(source, None)
            if entry:
                ca = context.Context(("DSHIELD", source), { "expire": 300, "alert_on_expire": True }, update = True, idmef = idmef)
                if ca.getUpdateCount() == 0:
                    ca.set("alert.classification.text", "IP source matching Dshield database")
                    ca.set("alert.correlation_alert.name", "IP source matching Dshield database")
                    ca.set("alert.assessment.impact.description", "Dshield gathered this IP address from firewall drops logs (%s - reports: %d, attacks: %d, first/last seen: %s - %s)" % (source, entry[0], entry[1], entry[2], entry[3]))
                    ca.set("alert.assessment.impact.severity", "high")

