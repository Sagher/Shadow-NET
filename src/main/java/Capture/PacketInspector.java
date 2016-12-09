package Capture;

import org.apache.log4j.Logger;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Http.Request;

import GeoIP.GeoIPv4;

import org.jnetpcap.protocol.tcpip.Tcp;

import Mongo.MongoTester;

public class PacketInspector implements JPacketHandler<Object> {
	public MongoTester mongoLogger = new MongoTester();

	public void nextPacket(JPacket packet, Object string) {

		Logger maliciousMatchLogger = Logger.getLogger(PacketInspector.class);
		Tcp tcp = new Tcp();
		Ip4 ip4 = new Ip4();
		Http http = new Http();

		String sourceIP;
		String destinationIP;
		String url;
		String direction;
		String maliciousType;
		boolean urlType;
		String location;
		String countryCode;

		if (packet.hasHeader(ip4) && packet.hasHeader(tcp)) {
			byte[] sIP = new byte[4];
			byte[] dIP = new byte[4];
			sIP = packet.getHeader(ip4).source();
			dIP = packet.getHeader(ip4).destination();

			sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(sIP);
			destinationIP = org.jnetpcap.packet.format.FormatUtils.ip(dIP);

			direction = getDirection(tcp.source());

			maliciousType = getMaliciousType(direction, sourceIP, destinationIP);

			/*
			 * If ip matches to and the list then resolve its Location and log
			 * to Db and also to the log file
			 * 
			 */

			if (maliciousType.length() != 4) {
				if (direction.equals("INCOMING")) {
					location = GeoIPv4.getLocation(sourceIP);
					countryCode = GeoIPv4.getCountryCode(sourceIP);
				} else {
					location = GeoIPv4.getLocation(destinationIP);
					countryCode = GeoIPv4.getCountryCode(sourceIP);

				}

				maliciousMatchLogger.info(sourceIP + ":" + tcp.source() + " \t" + destinationIP + ":"
						+ tcp.destination() + "\t" + direction + "\t" + maliciousType + "\t" + location);

				mongoLogger.logtoDb(sourceIP, destinationIP, tcp.source(), tcp.destination(), direction, maliciousType,
						location, countryCode);

			}

			maliciousMatchLogger.info(sourceIP + ":" + tcp.source() + " \t" + destinationIP + ":" + tcp.destination()
					+ "\t" + direction + "\t" + maliciousType);

			/*
			 * Resolve the destination of the outgoing url request and log to DB
			 * and log file
			 * 
			 */

			if (packet.hasHeader(http) && !http.isResponse()) {
				url = "http://" + http.fieldValue(Request.Host) + http.fieldValue(Request.RequestUrl);

				urlType = Check.isUrlMalicious(url);

				location = GeoIPv4.getLocation(destinationIP);

				countryCode = GeoIPv4.getCountryCode(destinationIP);

				maliciousMatchLogger
						.info(sourceIP + ":" + tcp.source() + " \t" + destinationIP + ":" + tcp.destination() + "\t"
								+ direction + "\t" + maliciousType + "\t" + location + "\t" + url + "\t" + urlType);

				/*
				 * Log to DB only if the ip is malicious or if the url is listed
				 * 
				 */
				if (urlType == true) {
					mongoLogger.logUrltoDb(sourceIP, destinationIP, tcp.source(), tcp.destination(), direction,
							maliciousType, url, urlType, location, countryCode);
				}

			}

			TcpReassemblyProcessor.processHttpPacket(sourceIP, destinationIP, tcp, mongoLogger);

		}

	}

	/*
	 * Checking the ip address against all of the arraylist
	 * 
	 */
	private String getMaliciousType(String direction, String sourceIP, String destinationIP) {
		if (direction.equals("INCOMING")) {
			return Check.isIPMalicious(sourceIP);

		} else {
			return Check.isIPMalicious(destinationIP);

		}
	}

	/*
	 * Determining the Direction of tcp packets
	 * 
	 */
	private String getDirection(int port) {
		if (port == 8080 | port == 443 | port == 80) {
			return "INCOMING";
		} else {
			return "OUTGOING";
		}
	}

}