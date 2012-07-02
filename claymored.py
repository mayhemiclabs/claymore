#!/usr/bin/env python
#
# claymored.py
# A script that sets up a DHCP server and runs a port scan on any client
# that requests an address. Designed to be used in a WiFi honeypot. 
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

import sys, os, daemon, syslog, argparse
from ConfigParser import SafeConfigParser
from dhcpserver import *

config_file = '/opt/claymore/claymore.ini'

parser = argparse.ArgumentParser(description='Claymore v0.1a',epilog="Copyright (c) 2012, Ben Jackson and Mayhemic Labs")
parser.add_argument('--debug', help='Debug mode')
args = parser.parse_args()

if not os.path.exists(config_file):
	sys.exit("Unable to locate " + config_file + " -- Terminating")

#with daemon.DaemonContext():
while True:
	syslog.openlog("claymored", 0, syslog.LOG_AUTH)

	syslog.syslog('Claymore Daemon Starting...')

	config = SafeConfigParser()
	config.read(config_file)

	server = Server(config)

	while True :
		server.GetNextDhcpPacket()
