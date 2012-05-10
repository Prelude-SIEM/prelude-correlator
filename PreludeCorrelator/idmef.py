# Copyright (C) 2009-2012 CS-SI. All Rights Reserved.
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

import tempfile, re
import PreludeEasy
from PreludeCorrelator import utils

_RegexType = type(re.compile(""))

class IDMEF(PreludeEasy.IDMEF):
        def __setstate__(self, dict):
                fd = tempfile.TemporaryFile("r+")
                fd.write(dict["idmef_encoded"])
                fd.seek(0)

                PreludeEasy.IDMEF.__init__(self)
                self.Read(fd)

                del(dict["idmef_encoded"])
                self.__dict__.update(dict)

        def __getstate__(self):
                fd = tempfile.TemporaryFile("r+")
                self.Write(fd)
                fd.seek(0)

                odict = self.__dict__.copy()
                odict["idmef_encoded"] = fd.read()
                del(odict["this"])

                return odict

        def getTime(self):
                itime = self.Get("alert.detect_time")
                if not itime:
                        itime = self.Get("alert.create_time")

                return itime

        def Get(self, path, flatten=True, replacement=None):
                path = PreludeEasy.IDMEFPath(path)

                value = path.Get(self)
                if not value:
                        if path.IsAmbiguous() and flatten:
                                return replacement or ()

                        return replacement

                if flatten and type(value) is tuple:
                        value = utils.flatten(value)

                return value

        def Set(self, path, value):
                if type(value) == PreludeEasy.IDMEFValue:
                        cur = self.Get(path)
                        if cur and value.Match(cur, PreludeEasy.IDMEFCriterion.OPERATOR_EQUAL) > 0:
                                return

                PreludeEasy.IDMEF.Set(self, path, value)

        def _match(self, path, needle):
                value = self.Get(path)

                if not isinstance(needle, _RegexType):
                        ret = value == needle
                else:
                        m = needle.search(value or "")
                        if not m:
                                return False

                        ret = m.groups()

                return ret

        def match(self, *args):
                if (len(args) % 2) != 0:
                        raise("Invalid number of arguments.")

                ret = []

                i = 0
                while i < len(args):
                        r = self._match(args[i], args[i + 1])
                        if r is False:
                                return None

                        elif isinstance(r, tuple):
                                ret.extend(r)

                        i += 2

                if ret:
                        return ret

                return True

        def alert(self):
                global prelude_client
                prelude_client.correlationAlert(self)

        def addAlertReference(self, idmef, auto_set_detect_time=True):
                if auto_set_detect_time is True:
                    intime = idmef.getTime()
                    curtime = self.getTime()
                    if (not curtime) or intime < curtime:
                        self.Set("alert.detect_time", intime)

                self.Set("alert.source(>>)", idmef.Get("alert.source"))
                self.Set("alert.target(>>)", idmef.Get("alert.target"))
                self.Set("alert.correlation_alert.alertident(>>).alertident", idmef.Get("alert.messageid"))
                self.Set("alert.correlation_alert.alertident(-1).analyzerid", idmef.Get("alert.analyzer(*).analyzerid")[-1])



def set_prelude_client(client):
        global prelude_client
        prelude_client = client
