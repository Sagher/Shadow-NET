package Capture;

import java.io.IOException;

import org.apache.log4j.Logger;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Http.Request;

import com.maxmind.geoip.Location;
import com.maxmind.geoip.LookupService;

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

		if (packet.hasHeader(ip4) && packet.hasHeader(tcp)) {
			byte[] sIP = new byte[4];
			byte[] dIP = new byte[4];
			sIP = packet.getHeader(ip4).source();
			dIP = packet.getHeader(ip4).destination();

			sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(sIP);
			destinationIP = org.jnetpcap.packet.format.FormatUtils.ip(dIP);

			direction = getDirection(tcp.source());

			maliciousType = getMaliciousType(direction, sourceIP, destinationIP);

			maliciousMatchLogger.info(sourceIP + ":" + tcp.source() + " \t" + destinationIP + ":" + tcp.destination()
					+ "\t" + direction + "\t" + maliciousType);

			
			if (maliciousType.length() != 4) {

				mongoLogger.logtoDb(sourceIP, destinationIP, tcp.source(), tcp.destination(), direction, maliciousType);
				maliciousMatchLogger.info(sourceIP + ":" + tcp.source() + " \t" + destinationIP + ":"
						+ tcp.destination() + "\t" + direction + "\t" + maliciousType);

			}

			if (packet.hasHeader(http) && !http.isResponse()) {
				url = "http://" + http.fieldValue(Request.Host) + http.fieldValue(Request.RequestUrl);

				urlType = Check.isUrlMalicious(url);

				maliciousMatchLogger.info(sourceIP + ":" + tcp.source() + " \t" + destinationIP + ":"
						+ tcp.destination() + "\t" + direction + "\t" + maliciousType + "\t" + url + "\t" + urlType);

				mongoLogger.logUrltoDb(sourceIP, destinationIP, tcp.source(), tcp.destination(), direction,
						maliciousType, url, urlType);

			}

			TcpReassemblyProcessor.processHttpPacket(sourceIP, destinationIP, tcp, mongoLogger);

		}

	}

	private String getMaliciousType(String direction, String sourceIP, String destinationIP) {
		if (direction.equals("INCOMING")) {
			return Check.isIPMalicious(sourceIP);

		} else {
			return Check.isIPMalicious(destinationIP);

		}
	}

	private String getDirection(int port) {
		if (port == 8080 | port == 443 | port == 80) {
			return "INCOMING";
		} else {
			return "OUTGOING";
		}
	}

	@SuppressWarnings("unused")
	private String getLocation(String ip) throws IOException {
		LookupService cl = new LookupService("/home/sagher/Desktop/GeoLiteCity.dat", LookupService.GEOIP_INDEX_CACHE);

		Location location = cl.getLocation(ip);

		return location.countryName;
	}

	

}
