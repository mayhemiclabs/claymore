#!/usr/bin/env python

import daemon

from claymore import claymore

with daemon.DaemonContext():
	claymore('/opt/claymore/claymore.ini')
