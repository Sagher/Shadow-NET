package Feeds;

import java.util.HashSet;

import org.json.JSONArray;
import org.json.JSONObject;

public class MainFeeds {

	public static HashSet<?> PROBING, MALWARES, WEB, DB, SIP, SSH, URLS, MD5;

	public static String Malware, Db, Probing, Sip, Ssh, Web, Urls, Md5;

	static ThreatFeedsFetcher malwares = new ThreatFeedsFetcher();
	static ThreatFeedsFetcher db = new ThreatFeedsFetcher();
	static ThreatFeedsFetcher probing = new ThreatFeedsFetcher();
	static ThreatFeedsFetcher sip = new ThreatFeedsFetcher();
	static ThreatFeedsFetcher ssh = new ThreatFeedsFetcher();
	static ThreatFeedsFetcher web = new ThreatFeedsFetcher();
	static ThreatFeedsFetcher urls = new ThreatFeedsFetcher();
	static ThreatFeedsFetcher md5 = new ThreatFeedsFetcher();

	static {
		try {
			Malware = malwares.fetchFeeds("http://api.myjson.com/bins/1r7z8", "MALWARE FEEDS");

			Db = db.fetchFeeds("http://api.myjson.com/bins/4bllg", "DB FEEDS");

			Probing = probing.fetchFeeds("http://api.myjson.com/bins/55e4k", "PROBING FEEDS");

			Sip = sip.fetchFeeds("http://api.myjson.com/bins/3fg6s", "SIP FEEDS");

			Ssh = ssh.fetchFeeds("http://api.myjson.com/bins/4uw1g", "SSH FEEDS");

			Web = web.fetchFeeds("http://api.myjson.com/bins/mpn8", "WEB FEEDS");

			Urls = urls.fetchFeeds("http://api.myjson.com/bins/538ys", "URLS FEEDS");

			Md5 = md5.fetchFeeds("http://api.myjson.com/bins/v2kk", "MD5 HASH FEEDS");

			PROBING = convertAndAddToSet(Probing, "ip");
			System.out.println("PROBES:" + PROBING.size());

			MALWARES = convertAndAddToSet(Malware, "ip");
			System.out.println("MALWARES:" + MALWARES.size());

			WEB = convertAndAddToSet(Web, "ip");
			System.out.println("WEB:" + WEB.size());

			DB = convertAndAddToSet(Db, "ip");
			System.out.println("DB:" + DB.size());

			SSH = convertAndAddToSet(Ssh, "ip");
			System.out.println("SSH:" + SSH.size());

			SIP = convertAndAddToSet(Sip, "ip");
			System.out.println("SIP:" + SIP.size());

			URLS = convertAndAddToSet(Urls, "url");
			System.out.println("URLS:" + URLS.size());

			MD5 = convertAndAddToSet(Md5, "hash");
			System.out.println("MD5:" + MD5.size());

		} catch (Exception e) {
			System.out.println(e);
		}

	}

	private static HashSet<String> convertAndAddToSet(String str, String key) {
		JSONArray jsonArr = new JSONArray(str);
		HashSet<String> list = new HashSet<String>();

		for (int i = 0; i < jsonArr.length(); i++) {
			JSONObject jsonObj = jsonArr.getJSONObject(i);
			list.add(jsonObj.get(key).toString());
		}
		return list;

	}

}
