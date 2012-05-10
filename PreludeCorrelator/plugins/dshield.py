# Copyright (C) 2009-2012 CS-SI. All Rights Reserved.
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
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING.  If not, write to
# the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.

import os, httplib, time
from PreludeCorrelator import context
from PreludeCorrelator import require
from PreludeCorrelator.idmef import IDMEF
from PreludeCorrelator.pluginmanager import Plugin


class DshieldPlugin(Plugin):
    DSHIELD_RELOAD = 7 * 24 * 60 * 60
    DSHIELD_SERVER = "www.dshield.org"
    DSHIELD_URI = "/ipsascii.html?limit=10000"
    DSHIELD_TIMEOUT = 10
    DSHIELD_FILENAME = require.get_data_filename(__name__, "dshield.dat")

    def __ipNormalize(self, ip):
        return ".".join([ i.lstrip("0") for i in ip.split(".") ])

    def __loadData(self, age=0):
        self.__iphash.clear()

        for line in open(self.__filename, "r"):
            if line[0] == '#':
                continue

            ip, reports, attacks, first_seen, last_seen = line.split('\t')
            self.__iphash[self.__ipNormalize(ip)] = (int(reports), int(attacks), first_seen, last_seen)

        if self.__reload > 0:
            context.Timer(self.__reload - age, self.__retrieveData).start()

    def __downloadData(self):
        self.info("Downloading host list, this might take some time...")

        try:
            con = httplib.HTTPConnection(self.__server, timeout=self.__timeout)
        except TypeError:
            con = httplib.HTTPConnection(self.__server)

        con.request("GET", self.__uri)
        r = con.getresponse()
        if r.status != 200:
            raise Exception, "Could not download DShield host list, error %d" % r.status

        fd = open(self.__filename, "w")
        fd.write(r.read())
        fd.close()

        self.info("Downloading done, processing data.")

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

        self.__iphash = { }
        self.__reload = self.getConfigValue("reload", self.DSHIELD_RELOAD, type=int)
        self.__filename = self.getConfigValue("filename", self.DSHIELD_FILENAME)
        self.__server = self.getConfigValue("server", self.DSHIELD_SERVER)
        self.__uri = self.getConfigValue("uri", self.DSHIELD_URI)
        self.__timeout = self.getConfigValue("timeout", self.DSHIELD_TIMEOUT, type=float)
        self.__retrieveData()

    def run(self, idmef):
        for source in idmef.Get("alert.source(*).node.address(*).address"):
            entry = self.__iphash.get(source, None)
            if entry:
                ca = context.Context(("DSHIELD", source), { "expire": 300, "alert_on_expire": True }, update = True, idmef = idmef)
                if ca.getUpdateCount() == 0:
                    ca.Set("alert.classification.text", "IP source matching Dshield database")
                    ca.Set("alert.correlation_alert.name", "IP source matching Dshield database")
                    ca.Set("alert.assessment.impact.description", "Dshield gathered this IP address from firewall drops logs (%s - reports: %d, attacks: %d, first/last seen: %s - %s)" % (source, entry[0], entry[1], entry[2], entry[3]))
                    ca.Set("alert.assessment.impact.severity", "high")

