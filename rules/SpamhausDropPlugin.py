# Copyright (C) 2009-2018 CS-SI. All Rights Reserved.
# Author: Yoann Vandoorselaere <yoann.v@prelude-ids.com>
# Author: Wes Young <wes@barely3am.com>
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

from preludecorrelator import require, log, download
from preludecorrelator.pluginmanager import Plugin, PluginDependenciesError
from preludecorrelator.context import Context

try:
    # Note:
    #   Versions 0.7.10 to 0.7.15 (inclusive) are known to be very slow
    #   due to a bug in python-netaddr.
    #   See https://github.com/drkjam/netaddr/issues/94 for more information
    import netaddr
except:
    raise PluginDependenciesError("missing netaddr module, https://pypi.python.org/pypi/netaddr")

logger = log.getLogger(__name__)

if tuple(int(x) for x in netaddr.__version__.split(".")) >= (0, 7):
    from netaddr import IPAddress, IPNetwork, IPSet
else:
    from netaddr import IP as IPAddress
    from netaddr import CIDR as IPNetwork

    class IPSet(list):
        def __contains__(self, y):
            for i in iter(self):
                if y in i:
                    return True

            return False

        def add(self, obj):
            self.append(obj)


class SpamhausDownload(download.HTTPDownloadCache):
    def __init__(self, filename, uri, timeout, reload):
        download.HTTPDownloadCache.__init__(self, "SpamhausDrop", filename, uri, timeout, reload, logger)

    def parse(self, data):
        mynets = IPSet()

        for line in data.split("\n"):
            if not line or line[0] == ';':
                continue

            ip, sbl = line.split(';')
            ip = IPNetwork(ip.strip())
            mynets.add(ip)

        return mynets


class SpamhausDropPlugin(Plugin):
    RELOAD = 7 * 24 * 60 * 60
    URI = "http://www.spamhaus.org/drop/drop.txt"
    TIMEOUT = 10

    def __init__(self, env):
        Plugin.__init__(self, env)

        reload = self.getConfigValue("reload", self.RELOAD, type=int)
        filename = self.getConfigValue("filename", require.get_data_filename("spamhaus_drop.dat",
                                                                             module=__name__,
                                                                             profile=env.profile))
        uri = self.getConfigValue("uri", self.URI)
        timeout = self.getConfigValue("timeout", self.TIMEOUT, type=float)

        self.__data = SpamhausDownload(filename, uri, timeout, reload)

    def run(self, idmef):
        for source in idmef.get("alert.source(*).node.address(*).address"):
            try:
                addr = IPAddress(source)
            except:
                continue

            if addr in self.__data.get():
                ca = Context(("SPAMHAUS", source), {"expire": 300, "alert_on_expire": True}, update=True, idmef=idmef)
                if ca.getUpdateCount() == 0:
                    ca.set("alert.classification.text", "IP source matching Spamhaus DROP dataset")
                    ca.set("alert.correlation_alert.name", "IP source matching Spamhaus DROP dataset")
                    ca.set("alert.assessment.impact.description",
                           "Spamhaus gathered this IP address in their DROP list - %s" % source)
                    ca.set("alert.assessment.impact.severity", "medium")
