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
		
		final OisemsMessage message = new OisemsMessage();
		message.setSender(sender_client_device.getPublicKey());
		message.setRecipient(recipient_client_device.getPublicKey());
		message.setTimestamp(System.currentTimeMillis());
		message.setMessage("This is something else Hello World!!!!!. Yes it is");
		sender_client_device.start(new OnClientReadyListener() {

			@Override
			public void onReady(OisemsClientDevice oisemsClientDevice) {
				oisemsClientDevice.sendMessage(message);
			}
			
		});
		while(true) {
			try {
				Thread.sleep(1000);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}
	
}
