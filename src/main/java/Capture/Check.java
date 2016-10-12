package Capture;

import Feeds.MainFeeds;

public class Check {
	public static String isIPMalicious(String ip) {

		if (!ip.equals("115.186.132.18")) {

			if (MainFeeds.Malwares.contains(ip)) {
				return "MALWARE";
			}
			if (MainFeeds.DB.contains(ip)) {
				return "DB";
			}
			if (MainFeeds.SIP.contains(ip)) {
				return "SIP";
			}
			if (MainFeeds.SSH.contains(ip)) {
				return "SSH";
			}
			if (MainFeeds.Web.contains(ip)) {
				return "WEB";
			}
			if (MainFeeds.Probing.contains(ip)) {
				return "PROBING";
			} else {
				return "none";

			}

		}
		return "NONE";

	}

	public static boolean isUrlMalicious(String url) {
		if (MainFeeds.Urls.contains(url)) {
			return true;
		} else {
			return false;
		}

	}

	public static boolean isMd5Matched(String md5) {
		if (MainFeeds.MD5.contains(md5)) {
			return true;
		} else {
			return false;
		}
	}

}
