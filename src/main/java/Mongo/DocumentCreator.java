package Mongo;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.apache.log4j.Logger;
import org.bson.Document;

public class DocumentCreator {

	private Logger mongoLogger = Logger.getLogger("debugLogger2");
	Document my_doc;

	DateFormat dateFormat = new SimpleDateFormat("dd/MM/yyyy, HH:mm:ss.SS");

	public void createDoc(String src, String dest, int tcpsrc, int tcpdest, String dir, String type, String location)

	{

		try {
			my_doc = new Document("time", dateFormat.format(new Date())).append("sourceIP", src)
					.append("destinationIP", dest).append("sourcePort", tcpsrc).append("destPort", tcpdest)
					.append("direction", dir).append("maliciousType", type).append("location", location);

		} catch (Exception e) {
			mongoLogger.debug("DOCUMENT CREATION FAILED");
		}

	}

	public void createUrlDoc(String sourceIP, String destinationIP, int source, int destination, String dir,
			String ipMalicious, String url, boolean urlMalicious, String location) {

		try {
			my_doc = new Document("time", dateFormat.format(new Date())).append("sourceIP", sourceIP)
					.append("destinationIP", destinationIP).append("sourcePort", source).append("destPort", destination)
					.append("direction", dir).append("maliciousType", ipMalicious).append("requestUrl", url)
					.append("urlCheck", urlMalicious).append("location", location);

		} catch (Exception e) {
			mongoLogger.debug("DOCUMENT CREATION FAILED");

		}

	}

	public void createPayloadDoc(String sourceIP, String destinationIP, int source, int destination,String dir, String ipMalicious,
			int segments, String md5, Boolean hashStatus, String location) {

		try {
			my_doc = new Document("time", dateFormat.format(new Date())).append("sourceIP", sourceIP)
					.append("destinationIP", destinationIP).append("sourcePort", source).append("destPort", destination)
					.append("direction", dir).append("maliciousType", ipMalicious).append("segments", segments)
					.append("hash", md5).append("hashStatus", hashStatus).append("location", location);

		} catch (Exception e) {
			mongoLogger.debug("DOCUMENT CREATION FAILED");
		}

	}

	public Document getDocument() {
		try {
			return my_doc;
		} catch (Exception e) {
			mongoLogger.error("No Document Created, Returning Empty Document");
		}
		return my_doc;

	}

}