
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;
import java.util.ArrayList;

public class ThreatFeedsFetcher {

	public static ArrayList<String> maliciousIPs = new ArrayList<String>();

	public static String url = "http://115.186.132.18:8080/TI/feeds?indicator=ip";

	static {

		String IP_container;// space delimited ip list

		try {

			HttpClient client = new DefaultHttpClient();

			HttpGet request = new HttpGet(url);

			HttpResponse Response = client.execute(request);

			HttpEntity entity = Response.getEntity();

			System.out.println("----------------------------------------");
			System.out.println(Response.getStatusLine());
			System.out.println("----------------------------------------");

			BufferedReader breader;

			try {

				breader = new BufferedReader(new InputStreamReader((Response.getEntity().getContent())));
				if (entity != null) {
					while ((IP_container = breader.readLine()) != null) {

						ThreatFeedsFetcher.maliciousIPs.add(IP_container);

					}

					breader.close();

				}
			} catch (IOException e) {
				e.printStackTrace();

			}

		} catch (ClientProtocolException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

}
