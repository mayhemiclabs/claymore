#!/usr/bin/env python

import time, os, re, nmap, smtplib, email.utils, daemon, syslog
from email.mime.text import MIMEText
from ConfigParser import SafeConfigParser

def scan_ip(ip):
	nm = nmap.PortScanner()

	try:
		nm.scan(ip)
		report = 'Scan result for ' + nm.command_line() + "\n"
		report += "----------------------------------------------------\n"
	except PortScannerError:
		report += 'Oh snap. nmap returned an error.'
	except:
		report += 'Oh snap. General error.'

	if len(nm.all_hosts()) == 0:
		report += 'Host came back as down. Which is odd, considering it just requested an address. Treachery may be afoot!'

	for host in nm.all_hosts():
		report += "Host: " + host + "(" + nm[host].hostname() + ")\n"
		report += "State: " + nm[host].state() + "\n"

		for proto in nm[host].all_protocols():
			report += "----------\n"
			report += "Protocol: " + proto + "\n"

			lport = nm[host][proto].keys()
			lport.sort()

			for port in lport:
				report += "Port: " + str(port) + "\tState: " + nm[host][proto][port]['state'] + "\n"
	return report

def send_email(text):

	global config

	server = smtplib.SMTP(config.get('mail','server_address'),config.get('mail','server_port'))

	msg = MIMEText(text)
	msg['To'] = email.utils.formataddr((config.get('mail','to_name'), config.get('mail','to_address')))
	msg['From'] = email.utils.formataddr((config.get('mail','from_name'), config.get('mail','from_address')))
	msg['Subject'] = 'Claymore Detonated'

	try:
		server.ehlo()

		if server.has_extn('STARTTLS'):
			server.starttls()
			server.ehlo()
			server.login(config.get('mail','server_login_user'), config.get('mail','server_login_password'))

		server.sendmail(config.get('mail','from_address'), [config.get('mail','to_address')], msg.as_string())

	finally:
		server.quit()

	return 0

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
				report = 'Claymore Detonated! - ' + line + "\n\n"
 				report += scan_ip(result.group(1))
				send_email(report)
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


