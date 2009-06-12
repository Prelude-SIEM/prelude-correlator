#!/usr/bin/env python

import os, glob
from distutils.command.install import install
from distutils.core import setup

PRELUDE_CORRELATOR_VERSION = "0.1"
LIBPRELUDE_REQUIRED_VERSION = "0.9.23"

class my_install(install):
        def run(self):
                if self.prefix:
                        self.conf_prefix = self.prefix + "/etc/prelude-correlator"
                else:
                        self.conf_prefix = "/etc/prelude-correlator"

                if not os.path.exists(self.prefix + "/var/lib/prelude-correlator"):
                        os.makedirs(self.prefix + "/var/lib/prelude-correlator")

                self.init_siteconfig()
                install.run(self)

        def init_siteconfig(self):
                config = open("PreludeCorrelator/siteconfig.py", "w")
                print >> config, "conf_dir = '%s'" % os.path.abspath(self.conf_prefix)
                print >> config, "ruleset_dir = '%s'" % os.path.abspath(self.conf_prefix + "/ruleset")
                print >> config, "lib_dir = '%s'" % os.path.abspath(self.prefix + "/var/lib/prelude-correlator")
                print >> config, "version = '%s'" % PRELUDE_CORRELATOR_VERSION
                print >> config, "libprelude_required_version = '%s'" % LIBPRELUDE_REQUIRED_VERSION
                config.close()

setup(name="prelude-corelator",
      version=PRELUDE_CORRELATOR_VERSION,
      maintainer = "Yoann Vandoorselaere",
      maintainer_email = "yoann.v@prelude-ids.com",
      url = "http://www.prelude-ids.com",
      packages=[ 'PreludeCorrelator'],
      data_files=[('etc/prelude-correlator/ruleset', glob.glob("ruleset/*.py"))],
      scripts=[ "scripts/prelude-correlator" ],
      cmdclass={ 'install': my_install })
