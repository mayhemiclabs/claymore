#!/usr/bin/env python
#
# dhcpserver.py
# A library for DHCP server related functions that are used by claymore
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

import threadpool, sqlite3
from pydhcplib.dhcp_packet import *
from pydhcplib.dhcp_network import *
from pydhcplib.type_ipv4 import ipv4
from pydhcplib.type_strlist import strlist
from bandit import *

class Server(DhcpServer):

	def __init__(self, config):
		self.pool = threadpool.ThreadPool(5)
		self.config = config
		DhcpServer.__init__(self, self.config.get('system','listen_address'), 68, 67)
		self.db = sqlite3.connect(self.config.get('system','address_database'))

	def HandleDhcpDiscover(self, req):
		rsp = DhcpPacket()
		rsp.CreateDhcpOfferPacketFrom(req)
		rsp = self.FillDhcpOptions(rsp)
		self.SendDhcpPacketTo(rsp,'255.255.255.255',68)

	def HandleDhcpRequest(self, req):
		rsp = DhcpPacket()
		rsp.CreateDhcpAckPacketFrom(req)
		rsp = self.FillDhcpOptions(rsp)
		self.SendDhcpPacketTo(rsp,'255.255.255.255',68)

		bandit = Bandit(self.config, ipv4(req.GetOption("request_ip_address")).str())
		bandit.scan()
		bandit.sendmail()		
		
	def FillDhcpOptions(self, rsp):
		rsp.SetOption("yiaddr", ipv4(self.DHCPDatabaseAddress(hwmac(rsp.GetOption("chaddr")[:6]).str())).list())
		rsp.SetOption("subnet_mask", ipv4(self.config.get('dhcpoptions','dhcp_subnet_mask')).list())
		rsp.SetOption("router", ipv4(self.config.get('dhcpoptions','dhcp_router')).list())
		rsp.SetOption("domain_name_server", ipv4(self.config.get('dhcpoptions','dhcp_dns_server')).list())
		rsp.SetOption("server_identifier", ipv4(self.config.get('dhcpoptions','dhcp_server_address')).list())
		rsp.SetOption("renewal_time_value", ipv4(1800).list())
		rsp.SetOption("rebinding_time_value", ipv4(2700).list())
		rsp.SetOption("ip_address_lease_time", ipv4(3600).list())
		return rsp

	def DHCPDatabaseAddress(self, hwmac):
		c = self.db.cursor()

		address = 0

		c.execute('SELECT address FROM addresses WHERE hwmac = ?', [hwmac])

		row = c.fetchone()

		if (row is not None):

			address = row[0]
			c.execute('UPDATE addresses SET last_seen = datetime() WHERE hwmac = ?', [hwmac])

		else:

			c.execute('SELECT MAX(address) FROM addresses')
			address = c.fetchone()[0]

			if (address >= ipv4(self.config.get('dhcpoptions','dhcp_pool_start')).int()):
				address = address + 1
			else:
				address = ipv4(self.config.get('dhcpoptions','dhcp_pool_start')).int()

			c.execute('INSERT INTO addresses(hwmac,address,first_seen,last_seen) VALUES (?,?,datetime(),datetime())', (hwmac, address))

		self.db.commit()

		return ipv4(address).str()
