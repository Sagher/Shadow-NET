import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapIf;

public class Main {

	public static final Logger debugger = Logger.getLogger("debugLogger");

	public static void main(String[] args) throws IOException {

		List<PcapIf> alldevs = new ArrayList<PcapIf>();
		StringBuilder errbuf = new StringBuilder();

		int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r != Pcap.OK || alldevs.isEmpty()) {
			debugger.debug("Can't read list of devices, error is " + errbuf.toString());
			return;
		}

		int i = 0;
		for (PcapIf device : alldevs) {
			System.out.println((i++) + "\t" + device.getName());
		}
		

		PcapIf device = alldevs.get(4);
		debugger.info(device.getName());

		int snaplen = 64 * 1024;
		int flags = Pcap.MODE_NON_PROMISCUOUS;
		int timeout = 10 * 10000;
		Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
		
		if (pcap == null) {
			debugger.debug("Error while opening device for capture: " + errbuf.toString());
			return;
		}
		
		String expression = "tcp port http";  
		int optimize = 0;         // 0 = false  
		int netmask = 0xFFFFFF00; // 255.255.255.0  
        PcapBpfProgram program = new PcapBpfProgram();
        if (pcap.compile(program, expression, optimize, netmask) != Pcap.OK) {  
        	  debugger.debug(pcap.getErr());  
        	  return;  
        	}  
       
        	          
        	if (pcap.setFilter(program) != Pcap.OK) {  
        		debugger.debug(pcap.getErr());  
        	  return;         
        	}  
	
		pcap.loop(-1, new PacketInspector(), "");
		pcap.close();

	}
}
