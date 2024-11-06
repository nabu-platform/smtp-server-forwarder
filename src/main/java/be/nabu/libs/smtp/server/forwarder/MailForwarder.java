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

import java.io.IOException;
import java.io.Writer;
import java.net.SocketException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import javax.net.ssl.SSLContext;

import org.apache.commons.net.smtp.SMTPClient;
import org.apache.commons.net.smtp.SMTPReply;
import org.apache.commons.net.smtp.SMTPSClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.MXRecord;
import org.xbill.DNS.Record;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

import be.nabu.libs.events.api.EventHandler;
import be.nabu.utils.io.IOUtils;
import be.nabu.utils.io.containers.chars.WritableStraightByteToCharContainer;
import be.nabu.utils.mime.api.Header;
import be.nabu.utils.mime.api.ModifiablePart;
import be.nabu.utils.mime.api.Part;
import be.nabu.utils.mime.impl.FormatException;
import be.nabu.utils.mime.impl.MimeFormatter;
import be.nabu.utils.mime.impl.MimeUtils;

public class MailForwarder implements EventHandler<Part, String> {

	private Logger logger = LoggerFactory.getLogger(getClass());
	
	// the internal domains are not forwarded
	private List<String> internalDomains;

	private SSLContext trustContext;
	
	private int connectionTimeout = 10000;
	private int socketTimeout = 20000;

	private String serverName;
	
	public MailForwarder(String serverName, SSLContext trustContext, String...internalDomains) {
		this.serverName = serverName;
		try {
			this.trustContext = trustContext == null ? SSLContext.getDefault() : trustContext;
		}
		catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
		this.internalDomains = Arrays.asList(internalDomains);
	}
	
	@Override
	public String handle(Part event) {
		Header [] from = MimeUtils.getHeaders("X-Original-From", event.getHeaders());
		if (from == null || from.length == 0) {
			logger.warn("No from found");
			return null;
		}
		Header [] to = MimeUtils.getHeaders("X-Original-To", event.getHeaders());
		
		if (event instanceof ModifiablePart) {
			((ModifiablePart) event).removeHeader(
				"X-Original-From",
				"X-Original-To",
				"X-Requested-Authorization-Id"
			);
		}
		
		if (to != null) {
			for (Header header : to) {
				String value = header.getValue();
				int indexOf = value.indexOf('@');
				if (indexOf > 0) {
					String domain = value.substring(indexOf + 1);
					if (!internalDomains.contains(domain)) {
						forward(domain, event, from[0].getValue(), value);
					}
				}
			}
		}
		
		return null;
	}
	
	@SuppressWarnings({ "unchecked", "rawtypes" })
	private void forward(String domain, Part email, String from, String to) {
		try {
			Record [] records = new Lookup(domain, Type.MX).run();
			if (records == null || records.length == 0) {
				logger.error("Could not resolve host: " + domain);
			}
			else {
				List<MXRecord> mxRecords = new ArrayList<MXRecord>();
				List recordList = Arrays.asList(records);
				mxRecords.addAll(recordList);
				Collections.sort(mxRecords, new Comparator<MXRecord>() {
					@Override
					public int compare(MXRecord o1, MXRecord o2) {
						return o1.getPriority() - o2.getPriority();
					}
				});
				for (MXRecord record : mxRecords) {
					String host = record.getTarget().toString(true);
					try {
						// MTA <> MTA transport is always on port 25 (as far as I can find)
						if (!attempt(host, email, from, to, false)) {
							logger.error("Failed to connect to: " + host + ", retrying other servers if any");
							continue;
						}
						break;
					}
					catch (Exception e) {
						logger.error("Failed for server " + host, e);
						break;
					}
				}
			}
		}
		catch (TextParseException e) {
			logger.error("Could not forward email, host not found: " + domain, e);
			e.printStackTrace();
		}
	}
	
	private boolean attempt(String targetServer, Part email, String from, String to, boolean secure) throws SocketException, IOException, FormatException {
		logger.debug("Attempting to send mail to: " + targetServer);
		
		SMTPClient client = trustContext == null ? new SMTPClient() : new SMTPSClient(secure, trustContext);
		client.setConnectTimeout(connectionTimeout);
		client.setDefaultTimeout(connectionTimeout);
		
		// 465 was never official for long
		int port = secure ? 587 : 25;
		
		logger.debug("Connecting on port: " + port);
		try {
			// connect
			client.connect(targetServer, port);
			if (!checkReply(client, "Could not connect to server", false)) {
				return false;
			}
		}
		catch (Exception e) {
			logger.error("Could not connect to server: " + targetServer, e);
			return false;
		}
		try {
			client.setSoTimeout(socketTimeout);
			String domain = serverName == null ? from.replaceAll(".*@", "") : serverName;
			logger.debug("Sending HELO from: {}", domain);
			client.helo(domain);
			if (checkReply(client, "Failed the helo command", false)) {
				
				// check if we want and can use starttls
				if (!secure && trustContext != null) {
					String[] replyStrings = client.getReplyStrings();
					for (String reply : replyStrings) {
						if (reply.contains("STARTTLS")) {
							logger.debug("Executing STARTTLS");
							if (!((SMTPSClient) client).execTLS()) {
								logger.debug("STARTTLS Failed");
								throw new RuntimeException("Secure context could not be established");
							}
						}
					}
				}
				
				logger.debug("Sending from: " + from);
				// set sender/recipients
				client.setSender(from);
				if (checkReply(client, "Failed to set sender: " + from, false)) {
					logger.debug("Sending to: " + to);
					client.addRecipient(to);
					if (checkReply(client, "Failed to set recipient: " + to, false)) {
						logger.debug("Sending data");
						// let's start writing...
						Writer writer = client.sendMessageData();
						MimeFormatter formatter = new MimeFormatter();
						WritableStraightByteToCharContainer output = new WritableStraightByteToCharContainer(IOUtils.wrap(writer));
						formatter.format(email, output);
						output.close();
						if (!client.completePendingCommand()) {
							logger.error("Could not send the data: " + client.getReply() + " : " + client.getReplyString());
						}
					}
				}
			}
		}
		catch (Exception e) {
			logger.error("Error occurred while sending mail: [" + client.getReplyCode() + "] " + client.getReplyString(), e);
		}
		finally {
			client.disconnect();
		}
		return true;
	}
	
	private boolean checkReply(SMTPClient client, String message, boolean throwException) {
		if (!SMTPReply.isPositiveCompletion(client.getReplyCode())) {
			if (throwException) {
				throw new RuntimeException("[" + client.getReplyCode() + "] " + client.getReplyString() + ": " + message);
			}
			else {
				logger.error("Failed positive check: [" + client.getReplyCode() + "] " + client.getReplyString() + ": " + message);
				return false;
			}
		}
		return true;
	}
}
