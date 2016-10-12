package Feeds;

import java.util.ArrayList;

public class MainFeeds {
	public static ArrayList<String> Malwares, DB, Probing, SIP, SSH, Web, Urls,MD5;

	static ThreatFeedsFetcher malwares = new ThreatFeedsFetcher();
	static ThreatFeedsFetcher db = new ThreatFeedsFetcher();
	static ThreatFeedsFetcher probing = new ThreatFeedsFetcher();
	static ThreatFeedsFetcher sip = new ThreatFeedsFetcher();
	static ThreatFeedsFetcher ssh = new ThreatFeedsFetcher();
	static ThreatFeedsFetcher web = new ThreatFeedsFetcher();
	static ThreatFeedsFetcher urls = new ThreatFeedsFetcher();
	static ThreatFeedsFetcher md5 = new ThreatFeedsFetcher();


	static {

		Malwares = malwares.fetchFeeds("http://115.186.132.18:8080/TI/feeds?indicator=ip&type=malware", "MALWARE FEEDS");

		DB = db.fetchFeeds("http://115.186.132.18:8080/TI/feeds?indicator=ip&type=db", "DB FEEDS");

		Probing = probing.fetchFeeds("http://115.186.132.18:8080/TI/feeds?indicator=ip&type=probing", "PROBING FEEDS");

		SIP = sip.fetchFeeds("http://115.186.132.18:8080/TI/feeds?indicator=ip&type=sip", "SIP FEEDS");

		SSH = ssh.fetchFeeds("http://115.186.132.18:8080/TI/feeds?indicator=ip&type=ssh", "SSH FEEDS");

		Web = web.fetchFeeds("http://115.186.132.18:8080/TI/feeds?indicator=ip&type=web", "WEB FEEDS");

		Urls = urls.fetchFeeds("http://115.186.132.18:8080/TI/feeds?indicator=url", "URLS FEEDS");
		
		MD5 = md5.fetchFeeds("http://115.186.132.18:8080/TI/feeds?indicator=md5", "MD5 HASH FEEDS");
		
	}

}
