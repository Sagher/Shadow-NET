package Mongo;

import com.mongodb.MongoClient;
import com.mongodb.client.MongoDatabase;

import org.apache.log4j.Logger;
import org.bson.Document;

public class MongoDbConnecter {

	private Logger mongoLogger = Logger.getLogger("debugLogger2");
	private int port = 27017;
	private String hostname = "localhost";
	private MongoDatabase db;
	public String collection;
	MongoClient mongoClient;

	public MongoDbConnecter() {
		mongoClient = new MongoClient();
		System.out.println("Creating Connection " + hostname + ":" + port);
		mongoLogger.info("Creating Connection " + hostname + ":" + port);

	}

	public void connectMongoDatabase(String dbname) {
		try {
			db = mongoClient.getDatabase(dbname);
			System.out.println("Connected to Database");
			mongoLogger.info("Connected to Database");

		} catch (Exception e) {
			System.err.println("Error Connecting Database ");
			mongoLogger.error("Error connection to Database");
		}
	}

	public void setCollection(String setcoll) {
		try {
			db.getCollection(setcoll);
			collection = setcoll;
			System.out.println("Collection " + setcoll + " selected successfully");
			mongoLogger.info("Collection " + setcoll + " selected successfully");

		} catch (Exception e) {
			System.err.println("Error Creating  Collection ");
			mongoLogger.error("Error Creating  Collection ");
		}
	}

	public void insertDocument(Document myDocument) {

		if (collection != "") {
			db.getCollection(collection).insertOne(myDocument);
			// System.out.println("Document Added to the Database");
		} else
			System.out.println("Please Select a Collection first");
			
	}

}