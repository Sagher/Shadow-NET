package Feeds;

import java.util.ArrayList;

public class MainFeeds {
	public static ArrayList<String> Malwares, DB, Probing, SIP, SSH, Web, Urls;

	static ThreatFeedsFetcher malwares = new ThreatFeedsFetcher();
	static ThreatFeedsFetcher db = new ThreatFeedsFetcher();
	static ThreatFeedsFetcher probing = new ThreatFeedsFetcher();
	static ThreatFeedsFetcher sip = new ThreatFeedsFetcher();
	static ThreatFeedsFetcher ssh = new ThreatFeedsFetcher();
	static ThreatFeedsFetcher web = new ThreatFeedsFetcher();
	static ThreatFeedsFetcher urls = new ThreatFeedsFetcher();

	static {

		Malwares = malwares.FeedsFetchers("http://115.186.132.18:8080/TI/feeds?indicator=ip&type=malware", "MALWARE FEEDS");

		DB = db.FeedsFetchers("http://115.186.132.18:8080/TI/feeds?indicator=ip&type=db", "DB FEEDS");

		Probing = probing.FeedsFetchers("http://115.186.132.18:8080/TI/feeds?indicator=ip&type=probing", "PROBING FEEDS");

		SIP = sip.FeedsFetchers("http://115.186.132.18:8080/TI/feeds?indicator=ip&type=sip", "SIP FEEDS");

		SSH = ssh.FeedsFetchers("http://115.186.132.18:8080/TI/feeds?indicator=ip&type=ssh", "SSH FEEDS");

		Web = web.FeedsFetchers("http://115.186.132.18:8080/TI/feeds?indicator=ip&type=web", "WEB FEEDS");

		Urls = urls.FeedsFetchers("http://115.186.132.18:8080/TI/feeds?indicator=url", "URLS FEEDS");
	}

}
