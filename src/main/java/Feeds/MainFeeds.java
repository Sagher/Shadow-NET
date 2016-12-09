package Feeds;

import java.util.HashSet;

import org.json.JSONArray;
import org.json.JSONObject;

public class MainFeeds {

	public static HashSet<String> PROBING, MALWARES, WEB, DB, SIP, SSH, URLS, MD5;

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
			Malware = malwares.fetchFeeds("http://115.186.132.18:8080/TI-Test/attacks/malware/ips", "MALWARE FEEDS");

			Db = db.fetchFeeds("http://115.186.132.18:8080/TI-Test/attacks/db/ips", "DB FEEDS");

			Probing = probing.fetchFeeds("http://115.186.132.18:8080/TI-Test/attacks/probing/ips", "PROBING FEEDS");

			Sip = sip.fetchFeeds("http://115.186.132.18:8080/TI-Test/attacks/sip/ips", "SIP FEEDS");

			Ssh = ssh.fetchFeeds("http://115.186.132.18:8080/TI-Test/attacks/ssh/ips", "SSH FEEDS");

			Web = web.fetchFeeds("http://115.186.132.18:8080/TI-Test/attacks/web/ips", "WEB FEEDS");

			Urls = urls.fetchFeeds("http://115.186.132.18:8080/TI-Test/attacks/urls", "URLS FEEDS");

			Md5 = md5.fetchFeeds("http://115.186.132.18:8080/TI-Test/attacks/malware/hashes", "MD5 HASH FEEDS");

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
