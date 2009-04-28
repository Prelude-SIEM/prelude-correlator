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
from pycor import siteconfig
from pycor.idmef import IDMEF
from pycor.plugins import Plugin
from pycor.context import Context, Timer


class DshieldPlugin(Plugin):
    DSHIELD_RELOAD = 7 * 24 * 60 * 60
    DSHIELD_SERVER = "www.dshield.org"
    DSHIELD_URI = "www.dshield.org/ipsascii.html?limit=10000"

    def __loadData(fname, age=0):
        cnt = 0
        self.__iphash.clear()

        for line in open(fname, "r"):
            if line[0] != '#':
                self.__iphash[line.split('\t')[0]] = True
                cnt = cnt + 1

        Timer(self.__reload - age, self.__retrieveData)

    def __retrieveData(self, timer=None):
        fname = siteconfig.lib_dir + "/dshield.dat"

        try:
            st = os.stat(fname)
            if time.time() - st.st_mtime < self.__reload:
                return self.__loadData(fname, time.time() - st.st_mtime)
        except:
            pass

        print("Downloading host list from dshield, this might take some time...")
        con = httplib.HTTPConnection(self.__server)
        con.request("GET", self.__uri)
        r = con.getresponse()
        if r.status != 200:
            return

        fd = open(fname, "w")
        fd.write(r.read())
        fd.close()

        print("Downloading done, processing data.")
        self.__loadData(fname)


    def __init__(self):
        self.__iphash = { }
        self.__reload = self.getConfigValue("reload", self.DSHIELD_RELOAD)
        self.__server = self.getConfigValue("server", self.DSHIELD_SERVER)
        self.__uri = self.getConfigValue("uri", self.DSHIELD_URI)

        self.__retrieveData()

    def run(self, idmef):
        for source in idmef.Get("alert.source(*).node.address(*).address"):
            if self.__iphash.has_key(source):
                ca = IDMEF()
                ca.Set("alert.source(>>)", idmef.Get("alert.source"))
                ca.Set("alert.target(>>)", idmef.Get("alert.target"))
                ca.Set("alert.correlation_alert.alertident(>>).alertident", idmef.Get("alert.messageid"))
                ca.Set("alert.correlation_alert.alertident(-1).analyzerid", idmef.Get("alert.analyzer(*).analyzerid")[-1])
                ca.Set("alert.classification.text", "IP source matching Dshield database")
                ca.Set("alert.correlation_alert.name", "IP source matching Dshield database")
                ca.Set("alert.assessment.impact.description", "Dshield gather IP addresses tagged from firewall logs drops")
                ca.Set("alert.assessment.impact.severity", "high")
                ca.alert()
