#!/usr/bin/env python

import time, os, re, nmap, smtplib, email.utils, daemon, syslog
from email.mime.text import MIMEText
from ConfigParser import SafeConfigParser
from bandit import *

def claymore(configfile='/opt/claymore/claymore.ini'):

	syslog.openlog("claymored", 0, syslog.LOG_AUTH)

	syslog.syslog('Claymore Daemon Starting...')

	global config
	config = SafeConfigParser()
	config.read(configfile)

	filename = config.get('system','log_file').strip("'")
	file = open(filename,'r')

	dhcp = re.compile("DHCPACK on (\d+\.\d+\.\d+\.\d+) to .+")

	st_results = os.stat(filename)
	st_size = st_results[6]
	file.seek(st_size)

	syslog.syslog('Claymore Daemon Ready!')

	while 1:

		where = file.tell()
		line = file.readline()

		if line:
			result = dhcp.search(line)
			if result is not None:
				line = line.rstrip()

				bandit = Bandit(result.group(1))
				bandit.scan()
				bandit.sendmail()

				syslog.syslog('Claymore Detonanted!')
		else:
			time.sleep(1)
			file.seek(where)
			new_size = os.stat(filename)[6]

			if new_size < st_size:
				syslog.syslog('Log file rotated. Recycling...')
				file.close()
				file = open(filename,'r')
				file.seek(new_size)
				syslog.syslog('Recycling Complete!')

			st_size = new_size


