# Copyright (C) 2009-2018 CS-SI. All Rights Reserved.
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
import re
import itertools
import operator
import prelude

from preludecorrelator import utils


_RegexType = type(re.compile(""))


class IDMEF(prelude.IDMEF):
    def getTime(self):
        itime = self.get("alert.detect_time")
        if not itime:
            itime = self.get("alert.create_time")

        return itime

    def get(self, path, flatten=True, replacement=None):
        path = prelude.IDMEFPath(path)

        value = path.get(self)
        if value is None:
            return replacement

        if flatten and type(value) is tuple:
            value = utils.flatten(value)

        return value

    def _match(self, path, needle):
        value = self.get(path)

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
            raise Exception("Invalid number of arguments.")

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

        self.set("alert.create_time", prelude.IDMEFTime())

        prelude_client.correlationAlert(self)

    def _getMergeList(self, path, idmef):
        newset = []
        sharedset = []

        curvalues = prelude.IDMEF.get(self, path)
        for newidx, newval in enumerate(prelude.IDMEF.get(idmef, path) or ()):
            have_match = False
            for curidx, curval in enumerate(curvalues):
                if curval == newval:
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
        for k, g in itertools.groupby(enumerate(sorted(set(value))), lambda i_x: i_x[0] - i_x[1]):
            ilist = list(map(operator.itemgetter(1), g))
            if len(ilist) > 1:
                has_range = True
                strl.append('%d-%d' % (ilist[0], ilist[-1]))
            else:
                strl.append('%d' % ilist[0])

        if has_range or len(strl) > 1:
            return "service.portlist", ",".join(strl)
        else:
            return "service.port", value[0]

    def _parsePortlist(self, portlist):
        ranges = (x.split("-") for x in portlist.split(","))
        plist = [i for r in ranges for i in range(int(r[0].strip()), int(r[-1].strip()) + 1)]
        return "service.port", plist

    def _defaultMerge(self, fpath, value):
        return fpath, value[0]

    def _getFilteredValue(self, basepath, fpath, reqval, idmef, preproc_func, filtered):
        for idx, value in enumerate(prelude.IDMEF.get(idmef, basepath + "." + fpath) or ()):
            if value:
                if value == reqval or reqval is None:
                    prelude.IDMEF.set(idmef, basepath + "(%d)." % idx + fpath, None)

            fpath2 = fpath
            if value and preproc_func:
                fpath2, value = preproc_func(value)

            if idx not in filtered:
                filtered[idx] = {}

            if fpath2 not in filtered[idx]:
                filtered[idx][fpath2] = []

            if value:
                filtered[idx][fpath2] += value if isinstance(value, list) else [value]

        return fpath

    def _mergeSet(self, path, idmef, filtered_path=()):
        filtered_new = {}
        filtered_cur = {}
        postproc = {}

        for (fpath, reqval), preproc_func, postproc_func in filtered_path:
            r1 = self._getFilteredValue(path, fpath, reqval, self, preproc_func, filtered_cur)
            r2 = self._getFilteredValue(path, fpath, reqval, idmef, preproc_func, filtered_new)

            postproc[r1 or r2] = postproc_func if postproc_func else self._defaultMerge

        unmodified_set, sharedset, newset = self._getMergeList(path, idmef)
        for idx, value in newset:
            prelude.IDMEF.set(self, path + "(>>)", value)
            for fpath, value in filtered_new.get(idx, {}).items():
                if value and fpath in postproc:
                    fpath, value = postproc[fpath](fpath, value)

                if value:
                    prelude.IDMEF.set(self, path + "(-1)." + fpath, value)

        for idx in unmodified_set:
            for fpath, value in filtered_cur.get(idx, {}).items():
                if value and fpath in postproc:
                    fpath, value = postproc[fpath](fpath, value)

                if value:
                    prelude.IDMEF.set(self, path + "(%d)." % idx + fpath, value)

        for idx, nidx in sharedset:
            common = defaultdict(list)
            for a, b in list(filtered_new.get(nidx, {}).items()) + list(filtered_cur.get(idx, {}).items()):
                common[a] += b

            for fpath, value in common.items():
                if value and fpath in postproc:
                    fpath, value = postproc[fpath](fpath, value)

                if value:
                    prelude.IDMEF.set(self, path + "(%d)." % idx + fpath, value)

        for idx, values in filtered_new.items():
            for fpath, value in values.items():
                if value and fpath in postproc:
                    fpath, value = postproc[fpath](fpath, value)

                if value:
                    prelude.IDMEF.set(idmef, path + "(%d)." % (idx) + fpath, value)

    def addAlertReference(self, idmef, auto_set_detect_time=True):
        if auto_set_detect_time is True:
            intime = idmef.getTime()
            curtime = self.getTime()
            if not curtime or intime < curtime:
                self.set("alert.detect_time", intime)

        st_filters = [(("process.pid", None), None, None),
                      (("service.name", "unknown"), None, None),
                      (("service.port", None), None, self._mergePort),
                      (("service.portlist", None), self._parsePortlist, self._mergePort)]

        self._mergeSet("alert.source", idmef, st_filters)
        self._mergeSet("alert.target", idmef, st_filters)

        self.set("alert.correlation_alert.alertident(>>).alertident", idmef.get("alert.messageid"))
        self.set("alert.correlation_alert.alertident(-1).analyzerid", idmef.get("alert.analyzer(*).analyzerid")[-1])


def set_prelude_client(client):
    global prelude_client
    prelude_client = client
