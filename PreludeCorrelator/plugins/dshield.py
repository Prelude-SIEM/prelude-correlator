# Copyright (C) 2009 PreludeIDS Technologies. All Rights Reserved.
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
from PreludeCorrelator import siteconfig
from PreludeCorrelator.idmef import IDMEF
from PreludeCorrelator.pluginmanager import Plugin
from PreludeCorrelator.context import Context, Timer


class DshieldPlugin(Plugin):
    DSHIELD_RELOAD = 7 * 24 * 60 * 60
    DSHIELD_SERVER = "www.dshield.org"
    DSHIELD_URI = "/ipsascii.html?limit=10000"
    DSHIELD_TIMEOUT = 10

    def __ipNormalize(self, ip):
        return ".".join([ i.lstrip("0") for i in ip.split(".") ])

    def __loadData(self, fname, age=0):
        cnt = 0
        self.__iphash.clear()

        for line in open(fname, "r"):
            if line[0] == '#':
                continue

            ip, reports, attacks, first_seen, last_seen = line.split('\t')
            self.__iphash[self.__ipNormalize(ip)] = (int(reports), int(attacks), first_seen, last_seen)

            cnt = cnt + 1

        Timer(self.__reload - age, self.__retrieveData).start()

    def __retrieveData(self, timer=None):
        fname = siteconfig.lib_dir + "/dshield.dat"

        try:
            st = os.stat(fname)
            if time.time() - st.st_mtime < self.__reload:
                return self.__loadData(fname, time.time() - st.st_mtime)
        except:
            pass

        self.info("Downloading host list, this might take some time...")

        con = httplib.HTTPConnection(self.__server, timeout=self.__timeout)
        con.request("GET", self.__uri)
        r = con.getresponse()
        if r.status != 200:
            raise Exception, "Could not download DShield host list, error %d" % r.status

        fd = open(fname, "w")
        fd.write(r.read())
        fd.close()

        self.info("Downloading done, processing data.")
        self.__loadData(fname)


    def __init__(self, env):
        Plugin.__init__(self, env)

        self.__iphash = { }
        self.__reload = self.getConfigValue("reload", self.DSHIELD_RELOAD)
        self.__server = self.getConfigValue("server", self.DSHIELD_SERVER)
        self.__uri = self.getConfigValue("uri", self.DSHIELD_URI)
        self.__timeout = float(self.getConfigValue("timeout", self.DSHIELD_TIMEOUT))
        self.__retrieveData()

    def run(self, idmef):
        for source in idmef.Get("alert.source(*).node.address(*).address"):
            entry = self.__iphash.get(source, None)
            if entry:
                ca = IDMEF()
                ca.addAlertReference(idmef)
                ca.Set("alert.classification.text", "IP source matching Dshield database")
                ca.Set("alert.correlation_alert.name", "IP source matching Dshield database")
                ca.Set("alert.detect_time", entry[2] + " 00:00:00Z")
                ca.Set("alert.assessment.impact.description", "Dshield gathered this IP address from firewall drops logs (%s - reports: %d, attacks: %d, first/last seen: %s - %s)" % (source, entry[0], entry[1], entry[2], entry[3]))
                ca.Set("alert.assessment.impact.severity", "high")
                ca.alert()
