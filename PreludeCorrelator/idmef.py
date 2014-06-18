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
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

from collections import defaultdict
import tempfile, re, itertools, operator
import PreludeEasy
import utils

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

        def GetAdditionalDataByMeaning(self, meaning):
            try:
                idx = self.Get("alert.additional_data(*).meaning").index(meaning)
            except:
                return None

            return self.Get("alert.additional_data(%d).data" % idx)

        def Get(self, path, flatten=True, replacement=None):
                path = PreludeEasy.IDMEFPath(path)

                value = path.Get(self)
                if value is None:
                        return replacement

                if flatten and type(value) is tuple:
                        value = utils.flatten(value)

                return value

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

        def _getMergeList(self, path, idmef):
                newset = []
                sharedset = []

                curvalues = PreludeEasy.IDMEF.Get(self, path)
                for newidx, newval in enumerate(PreludeEasy.IDMEF.Get(idmef, path) or ()):
                        have_match = False
                        for curidx, curval in enumerate(curvalues):
                                if curval.Match(newval, PreludeEasy.IDMEFCriterion.OPERATOR_EQUAL):
                                        sharedset.append((curidx, newidx))
                                        have_match = True

                        if not have_match:
                                newset.append((newidx, newval))

                unmodified_set = set(range(len(curvalues)))
                unmodified_set -= set([curidx for curidx, newidx in sharedset])

                return list(unmodified_set), sharedset, newset

        def _mergePort(self, fpath, value):
                strl = []
                has_range = False
                for k, g in itertools.groupby(enumerate(sorted(set(value))), lambda (i, x): i - x):
                        ilist = map(operator.itemgetter(1), g)
                        if len(ilist) > 1:
                                has_range = True
                                strl.append('%d-%d' % (ilist[0], ilist[-1]))
                        else:
                                strl.append('%d' % ilist[0])

                if has_range or len(strl) > 1:
                        return ("service.portlist", ",".join(strl))
                else:
                        return ("service.port", value[0])

        def _parsePortlist(self, portlist):
                ranges = (x.split("-") for x in portlist.split(","))
                plist = [ i for r in ranges for i in range(int(r[0].strip()), int(r[-1].strip()) + 1) ]
                return ("service.port", plist)

        def _defaultMerge(self, fpath, value):
                return (fpath, value[0])

        def _getFilteredValue(self, basepath, fpath, reqval, idmef, preproc_func, filtered):
                for idx, value in enumerate(PreludeEasy.IDMEF.Get(idmef, basepath + "." + fpath) or ()):
                        if value:
                                if value == reqval or reqval is None:
                                        PreludeEasy.IDMEF.Set(idmef, basepath + "(%d)." % idx + fpath, None)

                        if value and preproc_func:
                                fpath, value = preproc_func(value)

                        if not filtered.has_key(idx):
                                filtered[idx] = {}

                        if not filtered[idx].has_key(fpath):
                                filtered[idx][fpath] = []

                        if value:
                                filtered[idx][fpath] += value if isinstance(value, list) else [value]

                return fpath

        def _mergeSet(self, path, idmef, filtered_path=()):
                filtered_new = {}
                filtered_cur = {}
                postproc = {}

                for (fpath, reqval), preproc_func, postproc_func in filtered_path:
                        r1 = self._getFilteredValue(path, fpath, reqval, self, preproc_func, filtered_cur)
                        r2 = self._getFilteredValue(path, fpath, reqval, idmef, preproc_func, filtered_new)

                        if not postproc_func:
                                postproc[r1 or r2] = self._defaultMerge

                        if postproc_func:
                                postproc[r1 or r2] = postproc_func

                unmodified_set, sharedset, newset = self._getMergeList(path, idmef)
                for idx, value in newset:
                        PreludeEasy.IDMEF.Set(self, path + "(>>)", value)
                        for fpath, value in filtered_new.get(idx, {}).items():
                                if value and postproc.has_key(fpath):
                                        fpath, value = postproc[fpath](fpath, value)

                                if value:
                                        PreludeEasy.IDMEF.Set(self, path + "(-1)." + fpath, value)

                for idx in unmodified_set:
                        for fpath, value in filtered_cur.get(idx, {}).items():
                                if value and postproc.has_key(fpath):
                                        fpath, value = postproc[fpath](fpath, value)

                                if value:
                                        PreludeEasy.IDMEF.Set(self, path + "(%d)." % idx + fpath, value)

                common = defaultdict(list)
                for idx, nidx in sharedset:
                        common = defaultdict(list)
                        for a, b in filtered_new.get(nidx, {}).items() + filtered_cur.get(idx, {}).items():
                                common[a] += b

                        for fpath, value in common.items():
                                if value and postproc.has_key(fpath):
                                        fpath, value = postproc[fpath](fpath, value)

                                if value:
                                        PreludeEasy.IDMEF.Set(self, path + "(%d)." % idx + fpath, value)


                for idx, values in filtered_new.items():
                    for fpath, value in values.items():
                        if value and postproc.has_key(fpath):
                            fpath, value = postproc[fpath](fpath, value)

                        if value:
                                PreludeEasy.IDMEF.Set(idmef, path + "(%d)." % (idx) + fpath, value)


        def addAlertReference(self, idmef, auto_set_detect_time=True):
                if auto_set_detect_time is True:
                    intime = idmef.getTime()
                    curtime = self.getTime()
                    if (not curtime) or intime < curtime:
                        self.Set("alert.detect_time", intime)

                st_filters = [(("process.pid", None), None, None),
                              (("service.name", "unknown"), None, None),
                              (("service.port", None), None, self._mergePort),
                              (("service.portlist", None), self._parsePortlist, self._mergePort)]

                self._mergeSet("alert.source", idmef, st_filters)
                self._mergeSet("alert.target", idmef, st_filters)

                self.Set("alert.correlation_alert.alertident(>>).alertident", idmef.Get("alert.messageid"))
                self.Set("alert.correlation_alert.alertident(-1).analyzerid", idmef.Get("alert.analyzer(*).analyzerid")[-1])


def set_prelude_client(client):
        global prelude_client
        prelude_client = client
