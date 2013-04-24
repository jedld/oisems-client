package org.oisems.client;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;

public class OisemsClientDevice {

	public String getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(String publicKey) {
		this.publicKey = publicKey;
	}

	public String getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(String privateKey) {
		this.privateKey = privateKey;
	}

	String publicKey, privateKey;
	
	public void start() {
		try {
			Client client = new Client(this, new URI("ws://127.0.0.1:44444"));
			client.connectBlocking();
			System.out.println("register");
			HashMap <String,String>message = new HashMap<String, String>();
			message.put("cmd", "REGISTER");
			message.put("oisems_id", publicKey);
			client.send(Utils.mapToJSON(message));
		} catch (URISyntaxException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
