package Feeds;

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

	public  ArrayList<String> maliciousIPs = new ArrayList<String>();


	public  ArrayList<String> FeedsFetchers(String url,String type) {

		String IP_container;// space delimited ip list

		try {

			HttpClient client = new DefaultHttpClient();

			HttpGet request = new HttpGet(url);
			
			String encoding = DatatypeConverter.printBase64Binary("user:ti@user_TI".getBytes("UTF-8"));
	       
			request.setHeader("Authorization", "Basic " + encoding);

			HttpResponse Response = client.execute(request);

			HttpEntity entity = Response.getEntity();

			System.out.println("----------------------------------------");
			System.out.println(Response.getStatusLine());
			System.out.println(type+"\n----------------------------------------");

			BufferedReader breader;

			try {

				breader = new BufferedReader(new InputStreamReader((Response.getEntity().getContent())));
				if (entity != null) {
					while ((IP_container = breader.readLine()) != null) {

						maliciousIPs.add(IP_container);

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
		return maliciousIPs;
	}

}
