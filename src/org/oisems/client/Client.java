package org.oisems.client;

import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.binary.Base64;
import org.java_websocket.client.WebSocketClient;
import org.java_websocket.handshake.ServerHandshake;
import org.oisems.client.message.OisemsMessage;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class Client extends WebSocketClient {
	
	OisemsClientDevice device;
	String session_id;
	
	public Client(OisemsClientDevice device, URI serverURI) {
		super(serverURI);
		System.out.println("starting oisems-client");
		this.device = device;
	}

	@Override
	public void onClose(int arg0, String arg1, boolean arg2) {
		
	}

	@Override
	public void onError(Exception exception) {
			
	}

	@Override
	public void onMessage(String message) {
		System.out.println("onMessage = " + message);
		JsonParser parser = new JsonParser();
		JsonElement element = parser.parse(message);
		JsonObject response = element.getAsJsonObject();
		if (response.get("session_id")!=null) {
			String raw_session_id = element.getAsJsonObject().get("session_id").getAsString();
			byte[] raw_session = Base64.decodeBase64(raw_session_id);
			try {
				String unencryted_session_id = decrypt(raw_session, device.getPrivateKey());
				System.out.println("session_id = " + unencryted_session_id);
				this.session_id = unencryted_session_id;
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidKeySpecException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (BadPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		
		
	}

	private String decrypt(byte []raw_message, String privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		PKCS8EncodedKeySpec kspec = new PKCS8EncodedKeySpec(
				Base64.decodeBase64(privateKey));
		KeyFactory kf;
			kf = KeyFactory.getInstance("RSA");
			PrivateKey privKey = kf.generatePrivate(kspec);
		Cipher cipher = Cipher
				.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, privKey);
		byte[] decrypted = OisemsMessage.blockCipher(cipher, raw_message, Cipher.DECRYPT_MODE);
		ByteBuffer messageBuffer = ByteBuffer.wrap(decrypted);
		int message_length = messageBuffer.getInt();
		byte[] decrypted_message = new byte[message_length];
		messageBuffer.get(decrypted_message,0, message_length);
		String msg = new String(decrypted_message, Charset.forName("UTF-8"));
		return msg;
	}
	
	@Override
	public void onOpen(ServerHandshake handshake) {
		String content = new String(handshake.getContent(), Charset.forName("UTF-8"));
		System.out.println("server response = " + content);
	}

}
