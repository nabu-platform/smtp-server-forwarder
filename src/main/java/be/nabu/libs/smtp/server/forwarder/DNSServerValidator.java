/*
* Copyright (C) 2016 Alexander Verbruggen
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public License
* along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

package be.nabu.libs.smtp.server.forwarder;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.UnknownHostException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.nabu.libs.smtp.server.DefaultMailValidator;

public class DNSServerValidator extends DefaultMailValidator {

	private Logger logger = LoggerFactory.getLogger(getClass());
	
	@Override
	public boolean acceptConnection(String localServerName, String realm, String remoteServerName, SocketAddress remoteAddress) {
		try {
			InetAddress [] machines = InetAddress.getAllByName(remoteServerName);
			for (InetAddress address : machines) {
				if (address.getHostAddress().equals(((InetSocketAddress) remoteAddress).getAddress().getHostAddress())) {
					return true;
				}
			}
			return false;
		}
		catch (UnknownHostException e) {
			logger.error("Could not resolve host: " + remoteServerName, e);
			return false;
		}
	}

}
