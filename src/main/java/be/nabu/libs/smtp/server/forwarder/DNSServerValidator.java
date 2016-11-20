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
