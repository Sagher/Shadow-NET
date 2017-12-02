package com.shadow.capture;

import com.shadow.feeds.MainFeeds;

public class Check {

    public static String isIPMalicious(String ip) {

        if (MainFeeds.MALWARES.contains(ip)) {
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
        if (MainFeeds.WEB.contains(ip)) {
            return "WEB";
        }
        if (MainFeeds.PROBING.contains(ip)) {
            return "PROBING";
        } else {
            return "none";

        }

    }

    public static boolean isUrlMalicious(String url) {
        if (MainFeeds.URLS.contains(url)) {
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
