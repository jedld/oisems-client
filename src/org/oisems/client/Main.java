package org.oisems.client;

import org.apache.commons.codec.digest.DigestUtils;
import org.oisems.client.message.OisemsMessage;

public class Main {

	public static void main(String args[]) {
		OisemsClientDevice sender_client_device = Utils.createClientDevice();
		OisemsClientDevice recipient_client_device = Utils.createClientDevice();
		
		System.out.println("device public key = " + sender_client_device.getPublicKey());
		System.out.println("device private key = " + recipient_client_device.getPublicKey());
		
		OisemsMessage message = new OisemsMessage();
		message.setSender(sender_client_device.getPublicKey());
		message.setRecipient(recipient_client_device.getPublicKey());
		message.setTimestamp(System.currentTimeMillis());
		message.setMessage("Hello World!!!!!");
		message.setMessageId(DigestUtils.sha256Hex(Double.toString(Math.random())));
		System.out.println(message.toHexString(sender_client_device.getPrivateKey()));
	}
	
}
