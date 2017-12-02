package com.shadow.mongo;

import org.bson.Document;

public class MongoTester {

    MongoDbConnecter handler = new MongoDbConnecter();

    public MongoTester() {
        handler.connectMongoDatabase("db");
        handler.setCollection("MaliciousPackets");
    }

    public void logtoDb(String src, String dest, int i, int j, String direc, String type, String location,
            String countryCode) {

        DocumentCreator doc = new DocumentCreator();

        doc.createDoc(src, dest, i, j, direc, type, location, countryCode);

        Document createdDoc = doc.getDocument();

        handler.insertDocument(createdDoc);
    }

    public void logUrltoDb(String sourceIP, String destinationIP, int source, int destination, String dir,
            String ipMalicious, String url, boolean urlMalicious, String location, String countryCode) {
        DocumentCreator doc = new DocumentCreator();

        doc.createUrlDoc(sourceIP, destinationIP, source, destination, dir, ipMalicious, url, urlMalicious, location,
                countryCode);

        Document createdDoc = doc.getDocument();

        handler.insertDocument(createdDoc);

    }

    public void logPayload(String sourceIP, String destinationIP, int source, int destination, String dir,
            String ipMalicious, int segments, String md5, Boolean hashStatus, String location) {
        DocumentCreator doc = new DocumentCreator();
        doc.createPayloadDoc(sourceIP, destinationIP, source, destination, dir, ipMalicious, segments, md5, hashStatus,
                location);

        Document createdDoc = doc.getDocument();

        handler.insertDocument(createdDoc);

    }

}
