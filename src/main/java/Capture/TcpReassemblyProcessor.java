package Capture;

import java.util.ArrayList;
import java.util.HashMap;

import org.apache.log4j.Logger;
import org.jnetpcap.protocol.tcpip.Tcp;

import GeoIP.GeoIPv4;
import Mongo.MongoTester;

public class TcpReassemblyProcessor {
	static HashMap<Integer, ArrayList<String>> hm = new HashMap<Integer, ArrayList<String>>();
	static Logger maliciousMatchLogger = Logger.getLogger("maliciousMatchLogger");
	String direction;

	public static void processHttpPacket(String sourceIP, String destinationIP, Tcp tcp, MongoTester mongoLogger) {

		int key = (sourceIP + tcp.source() + destinationIP + tcp.destination()).hashCode();

		if (tcp.getPayloadLength() != 0) {
			if (hm.containsKey(key)) {
				byte[] dataa = tcp.getPayload();
				String data = new String(dataa);
				ArrayList<String> list = hm.get(key);
				list.add(data);
				hm.put(key, list);

			}
			if (!hm.containsKey(key)) {
				byte[] dataa = tcp.getPayload();
				String data = new String(dataa);
				if (data.startsWith("HTTP/1.1 200 OK")) {
					ArrayList<String> list = new ArrayList<String>();
					list.add("");
					hm.put(key, list);
				}
			}
		}

		if (tcp.getPayloadLength() == 0 && hm.containsKey(key)) {
			if (!(hm.isEmpty())) {

				int segments = hm.get(key).size();
				maliciousMatchLogger.info("No of segments: " + segments);

				StringBuilder payload = new StringBuilder();

				for (String s : hm.get(key)) {
					payload.append(s);
				}

				String data = new String(payload);
				// System.out.println(data);

				String hash = MD5(data);

				// System.out.println(hash);

				Boolean hashStatus = Check.isMd5Matched(hash);

				String location = GeoIPv4.getLocation(sourceIP);

				String direction = "INCOMING";

				maliciousMatchLogger.info(sourceIP + ":" + tcp.source() + " \t" + destinationIP + ":"
						+ tcp.destination() + "\t" + "\t" + Check.isIPMalicious(sourceIP) + "\t" + segments + "\t"
						+ hash + "\t" + hashStatus + "\t" + location);

				mongoLogger.logPayload(sourceIP, destinationIP, tcp.source(), tcp.destination(), direction,
						Check.isIPMalicious(sourceIP), segments, hash, hashStatus, location);

				hm.remove(key);

			}
		}

	}

	public static String MD5(String data) {
		try {
			java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
			byte[] array = md.digest(data.getBytes());
			StringBuffer sb = new StringBuffer();
			for (int i = 0; i < array.length; ++i) {
				sb.append(Integer.toHexString((array[i] & 0xFF) | 0x100).substring(1, 3));
			}
			return sb.toString();
		} catch (java.security.NoSuchAlgorithmException e) {
		}
		return null;
	}

}
