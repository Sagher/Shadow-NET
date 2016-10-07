package Mongo;


import org.bson.Document;

public class MongoTester {

	MongoDbConnecter handler = new MongoDbConnecter();

	
	public MongoTester() {
		handler.connectMongoDatabase("db");
		handler.setCollection("MaliciousPackets");
	}

	public void logtoDb(String src, String dest, int i, int j, String direc, String type) {

		DocumentCreator doc = new DocumentCreator();

		doc.createDoc(src, dest, i, j, direc, type);

		Document createdDoc = doc.getDocument();

		handler.insertDocument(createdDoc);
	}

	public void logUrltoDb(String sourceIP, String destinationIP, int source, int destination, String dir,
			String ipMalicious, String url, boolean urlMalicious) {
		DocumentCreator doc = new DocumentCreator();

		doc.createUrlDoc(sourceIP, destinationIP, source, destination, dir, ipMalicious, url, urlMalicious);

		Document createdDoc = doc.getDocument();

		handler.insertDocument(createdDoc);

	}

	public void logPayload(String sourceIP, String destinationIP, int source, int destination,String dir, String ipMalicious, int segments, String md5, Boolean hashStatus) {
		DocumentCreator doc = new DocumentCreator();
		doc.createPayloadDoc(sourceIP, destinationIP, source, destination, dir, ipMalicious, segments,md5, hashStatus);
		
		Document createdDoc = doc.getDocument();
		
		handler.insertDocument(createdDoc);
		
		
			

	}

	

}