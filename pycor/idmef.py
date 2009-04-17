# Copyright (C) 2009 PreludeIDS Technologies. All Rights Reserved.
# Author: Yoann Vandoorselaere <yoann.v@prelude-ids.com>
#
# This file is part of the Prewikka program.
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
from pycor import utils

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

        def Get(self, path, flatten=True, replacement=None):
                value = PreludeEasy.IDMEF.Get(self, path)
                if not value:
                        if flatten and not replacement:
                                return []
                        return replacement

                if flatten and type(value) is tuple:
                        value = utils.flatten(value)

                return value

        def Set(self, path, value):
                if type(value) == PreludeEasy.IDMEFValue:
                        cur = self.Get(path)
                        if cur and value.Match(cur, PreludeEasy.IDMEFCriterion.EQUAL) > 0:
                                return

                PreludeEasy.IDMEF.Set(self, path, value)

        def _match(self, path, needle):
                value = self.Get(path)

                if not isinstance(needle, _RegexType):
                        ret = value == needle
                else:
                        m = needle.match(value or "")
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
                        if not r:
                                return None

                        elif isinstance(r, tuple):
                                ret.extend(r)

                        i += 2

                return ret

        def reset(self):
                return

        def alert(self):
                global prelude_client
                prelude_client.correlationAlert(self)


def set_prelude_client(client):
        global prelude_client
        prelude_client = client
