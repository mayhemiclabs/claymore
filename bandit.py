#!/usr/bin/env python
#
# claymore.py
# A python script that monitors a DHCP log and port scans any assigned 
# addresses. Designed to be used in a self contained WiFi honeypot.
#
# Copyright (c) 2012, Ben Jackson and Mayhemic Labs - bbj@mayhemiclabs.com
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the author nor the names of contributors may be 
#       used to endorse or promote products derived from this software without 
#       specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import time, os, re, nmap, smtplib, email.utils, daemon, syslog
from email.mime.text import MIMEText
from ConfigParser import SafeConfigParser

class Bandit():
	def __init__(self, host):	
		self.target = host;		

	def scan(self):

		# Create a new nmap object
		nm = nmap.PortScanner()

		# Run a scan, catch it if it bombs out

		try:
			self.report = "Claymore Detonated! -- " + self.target + "\n\n"
			nm.scan(self.target)
			self.report += 'Scan result for ' + nm.command_line() + "\n"
			self.report += "----------------------------------------------------\n"
		except PortScannerError:
			self.report += 'Oh snap. nmap returned an error.'
		except:
			self.report += 'Oh snap. General error.'

		# If we don't have any scan results, something fishy is happening.
		if len(nm.all_hosts()) == 0:
			self.report += 'Host came back as down. Which is odd, considering it just requested an address. Treachery may be afoot!'

		# If we do have scan results, output them into a list
		for host in nm.all_hosts():
			self.report += "Host: " + host + "(" + nm[host].hostname() + ")\n"
			self.report += "State: " + nm[host].state() + "\n"

			for proto in nm[host].all_protocols():
				self.report += "----------\n"
				self.report += "Protocol: " + proto + "\n"

				lport = nm[host][proto].keys()
				lport.sort()

				for port in lport:
					self.report += "Port: " + str(port) + "\tState: " + nm[host][proto][port]['state'] + "\n"

	def sendmail(self):

		# Use the global SafeConfigParser variable
		global config

		# Set up a mail variable
		server = smtplib.SMTP(config.get('mail','server_address'),config.get('mail','server_port'))

		# Populate all the To and From addresses
		msg = MIMEText(self.report)
		msg['To'] = email.utils.formataddr((config.get('mail','to_name'), config.get('mail','to_address')))
		msg['From'] = email.utils.formataddr((config.get('mail','from_name'), config.get('mail','from_address')))
		msg['Subject'] = 'Claymore Detonated'

		# Log in if the user supports TLS
		try:
			server.ehlo()

			if server.has_extn('STARTTLS'):
				server.starttls()
				server.ehlo()
				server.login(config.get('mail','server_login_user'), config.get('mail','server_login_password'))

			server.sendmail(config.get('mail','from_address'), [config.get('mail','to_address')], msg.as_string())
	
		finally:
			server.quit()
	
	def getreport(self):
		return self.report
