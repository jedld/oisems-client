package org.oisems.client;

import org.apache.commons.codec.digest.DigestUtils;
import org.oisems.client.exception.MessageSenderNotVerifiedException;
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
		message.setMessage("This is something else Hello World!!!!!. Yes it is");
		
		
		byte mes_ser[] = message.toBytes(sender_client_device.getPrivateKey());
		
		OisemsMessage message2 = new OisemsMessage();
		try {
			message2.fromBytes(mes_ser, recipient_client_device.getPrivateKey());
		} catch (MessageSenderNotVerifiedException e) {
			System.out.println("Message Sender not verified");
		}
		System.out.println("decoded message = " + message2.getMessage());
		sender_client_device.start();
	}
	
}
