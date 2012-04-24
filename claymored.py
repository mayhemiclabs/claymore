#!/usr/bin/env python

import sys, os, daemon
from claymore import claymore

config_file = '/opt/claymore/claymore.ini'

if not os.path.exists(config_file):
	sys.exit("Unable to locate " + config_file + " -- Terminating")

with daemon.DaemonContext():
	claymore('/opt/claymore/claymore.ini')
