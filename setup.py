#!/usr/bin/env python

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

from ez_setup import use_setuptools
use_setuptools()

import os, sys, shutil
import urllib2
from setuptools import setup, find_packages
from setuptools.command.install import install
from setuptools.command.sdist import sdist

PRELUDE_CORRELATOR_VERSION = "1.0.2"


class my_sdist(sdist):
        def _downloadDatabase(self, dname, url, filename):

                print "Downloading %s database, this might take a while..." % (dname)
		r = urllib2.urlopen(url)
                fd = open(filename, "w")
                fd.write(r.read())
                fd.close()

        def __init__(self, *args, **kwargs):
                fin = os.popen('git log --summary --stat --no-merges --date=short', 'r')
                fout = open('ChangeLog', 'w')
                fout.write(fin.read())
                fout.close()

                self._downloadDatabase("DShield", "http://www.dshield.org/ipsascii.html?limit=10000", "PreludeCorrelator/plugins/dshield.dat")
                self._downloadDatabase("Spamhaus", "http://www.spamhaus.org/drop/drop.lasso", "PreludeCorrelator/plugins/spamhaus_drop.dat")

                sdist.__init__(self, *args)



class my_install(install):
        def __install_data(self):
                data_files = self.distribution.data_files
                self.distribution.data_files = []

                if self.prefix == "/usr":
                        prefix = "/"
                else:
                        prefix = self.prefix or ""

                root = self.root or ""
                for dir, files in data_files:
                        dir = os.path.abspath(root + os.sep + os.path.join(prefix, dir))

                        self.mkpath(dir)
                        for f in files:
                                dest = os.path.join(dir, os.path.basename(f))
                                if dest[-4:] == "conf" and os.path.exists(dest):
                                        dest += "-dist"

                                self.copy_file(f, dest)

        def run(self):
                prefix = self.prefix
                if prefix == "/usr":
                        prefix = ""

                self.init_siteconfig(prefix)
                self.__install_data()
                install.run(self)
                os.remove("PreludeCorrelator/siteconfig.py")

        def init_siteconfig(self, prefix):
                config = open("PreludeCorrelator/siteconfig.py", "w")
                print >> config, "conf_dir = '%s'" % os.path.abspath(prefix + "/etc/prelude-correlator")
                print >> config, "lib_dir = '%s'" % os.path.abspath(prefix + "/var/lib/prelude-correlator")
                config.close()

is_egg = "bdist_egg" in sys.argv
if is_egg:
        # Make sure we remove any trace of siteconfig.py
        try: shutil.rmtree("build")
        except: pass
        package_data = { '': [ "*.dat"], 'docs/sample-plugin': ["docs/sample-plugin/setup.py"] }
        data_files = [ ("", ["prelude-correlator.conf"]) ]
else:
        package_data = {}
        data_files = [ ("etc/prelude-correlator", ["prelude-correlator.conf"]),
                       ("var/lib/prelude-correlator", ["PreludeCorrelator/plugins/dshield.dat", "PreludeCorrelator/plugins/spamhaus_drop.dat"]) ]

setup(
        name="prelude-correlator",
        version=PRELUDE_CORRELATOR_VERSION,
        maintainer = "Prelude Team",
        maintainer_email = "contact.prelude@c-s.fr",
        author = "Yoann Vandoorselaere",
        author_email = "yoann.v@prelude-ids.com",
        license = "GPL",
        url = "https://www.prelude-ids.org",
        download_url = "https://www.prelude-ids.org/projects/prelude/files",
        description = "Prelude-Correlator perform real time correlation of events received by Prelude",
        long_description = """
Prelude-Correlator perform real time correlation of events received by Prelude.

Several isolated alerts, generated from different sensors, can thus
trigger a single CorrelationAlert should the events be related. This
CorrelationAlert then appears within the Prewikka interface and
indicates the potential target information via the set of correlation
rules.

Signature creation with Prelude-Correlator is based on the Python
programming language. Prelude's integrated correlation engine is
distributed with a default set of correlation rules, yet you still
have the opportunity to modify and create any correlation rule that
suits your needs.
""",
        classifiers = [ "Development Status :: 5 - Production/Stable",
                        "Environment :: Console",
                        "Intended Audience :: System Administrators",
                        "License :: OSI Approved :: GNU General Public License (GPL)",
                        "Natural Language :: English",
                        "Operating System :: OS Independent",
                        "Programming Language :: Python",
                        "Topic :: Security",
                        "Topic :: System :: Monitoring" ],

        packages = find_packages(),
        entry_points = {
                'console_scripts': [
                        'prelude-correlator = PreludeCorrelator.main:main',
                ],

                'PreludeCorrelator.plugins': [
                        'BruteForcePlugin = PreludeCorrelator.plugins.bruteforce:BruteForcePlugin',
                        'BusinessHourPlugin = PreludeCorrelator.plugins.businesshour:BusinessHourPlugin',
                        'DshieldPlugin = PreludeCorrelator.plugins.dshield:DshieldPlugin',
                        'FirewallPlugin = PreludeCorrelator.plugins.firewall:FirewallPlugin',
                        'OpenSSHAuthPlugin = PreludeCorrelator.plugins.opensshauth:OpenSSHAuthPlugin',
                        'EventScanPlugin = PreludeCorrelator.plugins.scan:EventScanPlugin',
                        'EventStormPlugin = PreludeCorrelator.plugins.scan:EventStormPlugin',
                        'EventSweepPlugin = PreludeCorrelator.plugins.scan:EventSweepPlugin',
                        'WormPlugin = PreludeCorrelator.plugins.worm:WormPlugin',
                        'SpamhausDropPlugin = PreludeCorrelator.plugins.spamhausdrop:SpamhausDropPlugin'
                ]
        },

        zip_safe = False,
        data_files = data_files,
        package_data = package_data,

        cmdclass = { 'sdist': my_sdist, 'install': my_install }
)
