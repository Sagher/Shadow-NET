package Feeds;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.log4j.Logger;


public class ThreatFeedsFetcher {

	Logger exceptionLogger = Logger.getLogger("debugLogger");

	public String maliciousIPs = new String();

	public String fetchFeeds(String url, String type) {

		String IP_container;// space delimited ip list

		try {

			HttpClient client = HttpClientBuilder.create().build();
			HttpGet request = new HttpGet(url);

			

			HttpResponse Response = client.execute(request);

			HttpEntity entity = Response.getEntity();

			System.out.println("----------------------------------------");
			System.out.println(Response.getStatusLine());
			System.out.println(type + "\n----------------------------------------");

			BufferedReader breader;

			try {

				breader = new BufferedReader(new InputStreamReader((Response.getEntity().getContent())));
				if (entity != null) {
					while ((IP_container = breader.readLine()) != null) {

						maliciousIPs=(IP_container);

					}

					breader.close();

				}
			} catch (IOException e) {
				exceptionLogger.debug("IOException", e);

			}

		} catch (ClientProtocolException e) {
			exceptionLogger.debug("ClientProtocolException", e);
		} catch (IOException e) {
			exceptionLogger.debug("IOException", e);
		}
		return maliciousIPs;
	}

}