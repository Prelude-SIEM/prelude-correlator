# Copyright (C) 2009-2012 CS-SI. All Rights Reserved.
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

import os, httplib, time
from PreludeCorrelator import require, log
from PreludeCorrelator.idmef import IDMEF
from PreludeCorrelator.pluginmanager import Plugin
from PreludeCorrelator.context import Context, Timer

import netaddr

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


class SpamhausDropPlugin(Plugin):
    RELOAD = 7 * 24 * 60 * 60
    SERVER = "www.spamhaus.org"
    URI = "/drop/drop.lasso"
    TIMEOUT = 10
    FILENAME = require.get_data_filename(__name__, "spamhaus_drop.dat")

    def __loadData(self, age=0):
        for line in open(self.__filename, "r"):
            if line[0] == ';':
                continue

            ip, sbl = line.split(';')
            ip = IPNetwork(ip.strip())
            self.__mynets.add(ip)

        if self.__reload > 0:
            Timer(self.__reload - age, self.__retrieveData).start()

    def __downloadData(self):
        logger.info("Downloading host list, this might take some time...")

        try:
            con = httplib.HTTPConnection(self.__server, timeout=self.__timeout)
        except TypeError:
            con = httplib.HTTPConnection(self.__server)

        con.request("GET", self.__uri)
        r = con.getresponse()
        if r.status != 200:
            raise Exception, "Could not download spamhaus DROP list, error %d" % r.status

        fd = open(self.__filename, "w")
        fd.write(r.read())
        fd.close()

        logger.info("Downloading done, processing data.")

    def __retrieveData(self, timer=None):
        try:
            st = os.stat(self.__filename)
            if self.__reload <= 0 or time.time() - st.st_mtime < self.__reload:
                return self.__loadData(time.time() - st.st_mtime)
        except OSError:
            pass

        self.__downloadData()
        self.__loadData()


    def __init__(self, env):
        Plugin.__init__(self, env)

        self.__mynets = IPSet()
        self.__reload = self.getConfigValue("reload", self.RELOAD, type=int)
        self.__filename = self.getConfigValue("filename", self.FILENAME)
        self.__server = self.getConfigValue("server", self.SERVER)
        self.__uri = self.getConfigValue("uri", self.URI)
        self.__timeout = self.getConfigValue("timeout", self.TIMEOUT, type=float)
        self.__retrieveData()

    def run(self, idmef):
        for source in idmef.Get("alert.source(*).node.address(*).address"):
            try:
                addr = IPAddress(source)
            except:
                continue

            if addr in self.__mynets:
                ca = Context(("SPAMHAUS", source), { "expire": 300, "alert_on_expire": True }, update = True, idmef = idmef)
                if ca.getUpdateCount() == 0:
                        ca.Set("alert.classification.text", "IP source matching Spamhaus DROP dataset")
                        ca.Set("alert.correlation_alert.name", "IP source matching Spamhaus DROP dataset")
                        ca.Set("alert.assessment.impact.description", "Spamhaus gathered this IP address in their DROP list - %s" % (source))
                        ca.Set("alert.assessment.impact.severity", "medium")
