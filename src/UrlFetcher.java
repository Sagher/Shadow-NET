
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

public class UrlFetcher {

	public static ArrayList<String> maliciousUrls = new ArrayList<String>();

	public static String url = "http://115.186.132.18:8080/TI/feeds?indicator=url";

	static {

		String URL_container;// space delimited ip list

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
					while ((URL_container = breader.readLine()) != null) {

						UrlFetcher.maliciousUrls.add(URL_container);
						UrlFetcher.maliciousUrls.add("http://115.186.132.18:8080/TI/feeds?indicator=url");

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
