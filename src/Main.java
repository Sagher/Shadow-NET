import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

public class Main {
	public static Logger debugger = Logger.getLogger("debugLogger");
	public static Logger matchLog = Logger.getLogger("infoLogger");
	
	public static void main(String[] args) throws IOException {

		
		List<PcapIf> alldevs = new ArrayList<PcapIf>(); 
		
		StringBuilder errbuf = new StringBuilder(); 
		int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r != Pcap.OK || alldevs.isEmpty()) {
		debugger.debug("Can't read list of devices, error is %s"+errbuf.toString());
			return;
		}

		PcapIf device = alldevs.get(1); 
		matchLog.info(device.getName());

		int snaplen = 64 * 1024; 
		int flags = Pcap.MODE_PROMISCUOUS; 
		int timeout = 10 * 1000; 
		Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

		if (pcap == null) {
		debugger.debug("Error while opening device for capture: " + errbuf.toString());
			return;
		}
		pcap.loop(-1, new PacketInspector(), "");

		pcap.close();

	}
}
