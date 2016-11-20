package be.nabu.libs.smtp.server.forwarder;

import java.io.IOException;
import java.io.Writer;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
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
import be.nabu.libs.smtp.server.SMTPException;
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
	
	private int connectionTimeout = 60000;
	private int socketTimeout = 60000;

	private String serverName;

	public MailForwarder(String serverName, SSLContext trustContext, String...internalDomains) {
		try {
			this.serverName = serverName == null ? InetAddress.getLocalHost().getHostName() : serverName;
		}
		catch (UnknownHostException e) {
			throw new IllegalArgumentException("Expecting host", e);
		}
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
					System.out.println("ATTEMPTING: " + record.getTarget().toString());
					try {
						attempt(record.getTarget().toString(), email, from, to, true);
					}
					catch (FormatException e) {
						throw new SMTPException(500, e);
					}
					catch (Exception e) {
						// keep trying
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
		SMTPClient client = trustContext == null ? new SMTPClient() : new SMTPSClient(!secure, trustContext);
		client.setConnectTimeout(connectionTimeout);
		client.setDefaultTimeout(connectionTimeout);
		
		// 465 was never official for long
		int port = secure ? 587 : 25;
		
		// connect
		client.connect(targetServer, port);
		checkReply(client, "Could not connect to server");
		
		try {
			client.setSoTimeout(socketTimeout);
			client.helo(serverName);
			checkReply(client, "Failed the helo command");
			
			// check if we want and can use starttls
			if (!secure && trustContext != null) {
				String[] replyStrings = client.getReplyStrings();
				for (String reply : replyStrings) {
					if (reply.contains("STARTTLS")) {
						if (!((SMTPSClient) client).execTLS()) {
							throw new RuntimeException("Secure context could not be established");
						}
					}
				}
			}
			
			// set sender/recipients
			client.setSender(from);
			checkReply(client, "Failed to set sender: " + from);
			
			client.addRecipient(to);
			checkReply(client, "Failed to set recipient: " + to);
			
			// let's start writing...
			Writer writer = client.sendMessageData();
			MimeFormatter formatter = new MimeFormatter();
			WritableStraightByteToCharContainer output = new WritableStraightByteToCharContainer(IOUtils.wrap(writer));
			formatter.format(email, output);
			output.close();
			if (!client.completePendingCommand()) {
				throw new RuntimeException("Could not send the data: " + client.getReply() + " : " + client.getReplyString());
			}
		}
		finally {
			client.disconnect();
		}
	}
	
	private void checkReply(SMTPClient client, String message) {
		if (!SMTPReply.isPositiveCompletion(client.getReplyCode())) {
			throw new RuntimeException("[" + client.getReplyCode() + "] " + client.getReplyString() + ": " + message);
		}
	}
}