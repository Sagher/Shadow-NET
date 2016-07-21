package Capture;

import org.apache.log4j.Logger;
import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Http.Request;
import org.jnetpcap.protocol.tcpip.Tcp;

public class PacketInspector implements PcapPacketHandler<Object> {
	public Logger exceptionLog = Logger.getLogger("debugLogger");
	static Logger matchLog = Logger.getLogger("maliciousMatchLogger");
	Pcap pcap;

	String ipInfoMatch;
	String sourceIP;
	String destinationIP;

	@Override
	public void nextPacket(PcapPacket packet, Object string) {
		PcapPacket p = packet;
		Tcp tcp = new Tcp();
		Ip4 ip4 = new Ip4();
		Http http = new Http();

		if (p.hasHeader(ip4) && p.hasHeader(tcp)) {
			byte[] sIP = new byte[4];
			byte[] dIP = new byte[4];
			sIP = packet.getHeader(ip4).source();
			dIP = packet.getHeader(ip4).destination();

			sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(sIP);
			destinationIP = org.jnetpcap.packet.format.FormatUtils.ip(dIP);

			ipInfoMatch = sourceIP + " \t" + destinationIP + "\t" + Check.isIPMalicious(sourceIP);
			matchLog.info(ipInfoMatch);
			System.out.println(ipInfoMatch);

			if (p.hasHeader(tcp) && p.hasHeader(http) && !http.isResponse()) {
				String url = "http://" + http.fieldValue(Request.Host) + http.fieldValue(Request.RequestUrl);
				String urlMatchInfo = url + "\t" + Check.isUrlMalicious(url);

				matchLog.info(ipInfoMatch + "\t" + urlMatchInfo);

				System.out.println(ipInfoMatch + "\t" + urlMatchInfo);
			}

		}

	}

}
