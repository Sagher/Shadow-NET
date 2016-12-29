package GeoIP;

import com.maxmind.geoip.Location;
import com.maxmind.geoip.LookupService;

import java.io.IOException;
import java.util.Locale;

public class GeoIPv4 {

	public static Location resolved;

	private static LookupService lookUp;

	static {
		try {
			lookUp = new LookupService(GeoIPv4.class.getResource("/GeoLiteCity.dat").getPath(),
					LookupService.GEOIP_MEMORY_CACHE);

			System.out.println("GeoIP Database loaded: " + lookUp.getDatabaseInfo());
		} catch (IOException e) {
			System.out.println("Could not load geo ip database: " + e.getMessage());
		}
	}

	public static String getLocation(String ipAddress) {
		if (lookUp.getLocation(ipAddress) != null) {
			resolved = lookUp.getLocation(ipAddress);
			return resolved.countryName;
		} else {
			resolved = null;
		}
		return "N/A";
	}
	
	public static String getCountryCode(String ipAddress) {
		if (lookUp.getLocation(ipAddress) != null) {
			resolved = lookUp.getLocation(ipAddress);
			Locale countryCode = new Locale("en", resolved.countryCode);
			if (resolved.countryCode.equals("EU")) {
				return resolved.countryCode;
			} else {
				String loc = countryCode.getISO3Country();
				return loc;
			}
		} else {
			resolved = null;
		}
		return "N/A";
	}
}