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


_REGEX_CACHE = {}


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

        def Set(self, path, value):
                if type(value) == PreludeEasy.IDMEFValue:
                        cur = self.Get(path)
                        if cur and value.Match(cur, PreludeEasy.IDMEFCriterion.EQUAL) > 0:
                                return

                PreludeEasy.IDMEF.Set(self, path, value)

        def match(self, *args):
                if (len(args) % 2) != 0:
                        raise("Invalid number of arguments.")

                i = 0
                while i < len(args):
                        if _REGEX_CACHE.has_key(args[i + 1]):
                            r = _REGEX_CACHE[args[i + 1]]
                        else:
                            r = _REGEX_CACHE[args[i + 1]] = re.compile(args[i + 1])

                        value = self.Get(args[i])
                        if not value or not r.match(value):
                                return False

                        i+= 2

                return True

        def reset(self):
                self._cache = { }

        def alert(self):
                global prelude_client
                prelude_client.correlationAlert(self)



def set_prelude_client(client):
        global prelude_client
        prelude_client = client
