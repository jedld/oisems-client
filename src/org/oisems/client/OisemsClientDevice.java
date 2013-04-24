package org.oisems.client;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;

import org.apache.commons.codec.binary.Base64;
import org.oisems.client.message.OisemsMessage;

public class OisemsClientDevice implements OnNewSessionListener {
	
	Client client;
	String sessionId;
	
	OnClientReadyListener onClientReadyListener;
	
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
	
	public void sendMessage(OisemsMessage message) {
		HashMap <String,String> request = new HashMap<String,String>();
		request.put("cmd", "SENDMESSAGE");
		request.put("oisems_id", publicKey);
		request.put("session_id", sessionId);
		request.put("message", Base64.encodeBase64String(message.toBytes(privateKey)));
		client.send(Utils.mapToJSON(request));
	}
	
	public void start(OnClientReadyListener onClientReadyListener) {
		try {
			client = new Client(this, new URI("ws://127.0.0.1:44444"));
			client.connectBlocking();
			this.onClientReadyListener = onClientReadyListener;
			client.setListener(this);
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
 
	@Override
	public void onSession(String session_id) {
		this.sessionId = session_id;
		if (onClientReadyListener!=null) {
			onClientReadyListener.onReady(this);
		}
	}
}
