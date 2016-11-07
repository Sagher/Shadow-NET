package Capture;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

public class Main {
	public static final Logger exceptionLogger = Logger.getLogger("debugLogger");

	public static void main(String[] args) throws IOException {
		List<PcapIf> alldevs = new ArrayList<PcapIf>();
		StringBuilder errbuf = new StringBuilder();

		int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r != Pcap.OK || alldevs.isEmpty()) {
			exceptionLogger.error("Can't read list of devices, error is " + errbuf.toString());
			return;
		}

		System.out.println("Network devices found:");

		int i = 0;
		for (PcapIf device : alldevs) {
			exceptionLogger.info((i) + "\t" + device.getName());
			System.out.println((i) + "\t" + device.getName());
			i++;
		}

		int snaplen = 64 * 1024;
		int flags = Pcap.MODE_NON_PROMISCUOUS;
		int timeout = 10 * 1;
		String device = "eth0";
		exceptionLogger.info("Device Selected: "+device);
		Pcap pcap = Pcap.openLive(device, snaplen, flags, timeout, errbuf);

		if (pcap == null) {
			exceptionLogger.error("Error while opening device for capture: " + errbuf.toString());
			return;
		}
		pcap.loop(-1, new PacketInspector(), " ");

		pcap.close();
	}
}
