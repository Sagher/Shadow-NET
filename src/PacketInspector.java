package jnet;

import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Http.Request;
import org.jnetpcap.protocol.tcpip.Tcp;

public class PacketInspector {
    public  Logger exceptionLog = Logger.getLogger("debugLogger");
    static  Logger matchLog = Logger.getLogger("maliciousMatchLogger");
	Pcap pcap;

	public void pcapProcess() {
		
		List<PcapIf> alldevs = new ArrayList<PcapIf>();
		StringBuilder err = new StringBuilder();
		int r = Pcap.findAllDevs(alldevs, err);
		if (r != Pcap.OK || alldevs.isEmpty()) {
			exceptionLog.debug("Can't read list of devices, error is " + err.toString());
			return;
		}


		PcapIf device = alldevs.get(0); 

		int snaplen = 64 * 1024;
		int flags = Pcap.MODE_PROMISCUOUS; 
		int timeout = 10 * 1000;
		pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, err);

		if (pcap == null) {
			exceptionLog.debug("Error while opening device for capture: " + err.toString());
			return;
		}

		PcapPacketHandler<String> packetHandler = new PcapPacketHandler<String>() {

			String ipInfoMatch;
			String sourceIP;
			String destinationIP;
			
			public void nextPacket(PcapPacket packet, String arg1) {

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
				    ipInfoMatch = sourceIP + " \t" + destinationIP + "\t" + isIPMalicious(destinationIP);
					
					matchLog.info(ipInfoMatch);
					
				
					if (p.hasHeader(tcp) && p.hasHeader(http) && !http.isResponse()) {
						String url = "http://" + http.fieldValue(Request.Host) + http.fieldValue(Request.RequestUrl);
						String urlMatchInfo = url + "\t" + isUrlMalicious(url);
						
						matchLog.info(ipInfoMatch+"\t"+urlMatchInfo);
					}
						
				}
				
			}
			
		};

		pcap.loop(-1, packetHandler, "");

		pcap.close();
	}

	public boolean isIPMalicious(String dest) {

		if (ThreatFeedsFetcher.maliciousIPs.contains(dest)) {
			return true;
		} else {
			return false;
		}

	}
	
	public boolean isUrlMalicious(String url) {
		if (UrlFetcher.maliciousUrls.contains(url)) {
			return true;
		} else {
			return false;
		}

	}
}
