package org.oisems.client.message;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.binary.Base64;

public class OisemsMessage {
	public static final int MAX_SIZE = 2953;
	String sender;
	String recipient;
	String message;
	String messageId;
	int part;
	long timestamp;

	public String getSender() {
		return sender;
	}

	public void setSender(String sender) {
		this.sender = sender;
	}

	public String getRecipient() {
		return recipient;
	}

	public void setRecipient(String recipient) {
		this.recipient = recipient;
	}

	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}

	public String getMessageId() {
		return messageId;
	}

	public void setMessageId(String messageId) {
		this.messageId = messageId;
	}

	public long getTimestamp() {
		return timestamp;
	}

	public void setTimestamp(long timestamp) {
		this.timestamp = timestamp;
	}

	public byte[] getMessagePayload() {
		try {
			PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(
					new X509EncodedKeySpec(Base64.decodeBase64(recipient)));
			Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);

			byte[] header = stringToBytesASCII("OISEMS");
			MessageDigest md = MessageDigest.getInstance("MD5");
			byte[] salt = md.digest(Double.toString(Math.random()).getBytes());

			ByteBuffer buffer = ByteBuffer.allocate(64 *20);
			ByteBuffer finalbuffer = ByteBuffer.allocate(64 * 20);
			buffer.put(header);
			buffer.put(salt);
			buffer.put(message.getBytes(Charset.forName("UTF-8")));
			finalbuffer.put(cipher.doFinal(buffer.array()));
			
			return finalbuffer.array();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
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
		return null;
	}

	public void fromBytes(byte message[], String privateKey) {
		ByteBuffer buffer = ByteBuffer.wrap(message);
		int version = buffer.get();
		System.out.println("OISEMS version " + version);
		byte senderPublicKey[] = new byte[94];
		byte recipientPublicKey[] = new byte[94];
		byte messageId[] = new byte[64];
		byte ds[] = new byte[64];
		byte raw_message[] = new byte[64*20];
		buffer.get(senderPublicKey);
		buffer.get(recipientPublicKey);
		buffer.get(messageId);
		long timestamp = buffer.getLong();
		part = buffer.getInt();
		buffer.get(ds);
		buffer.get(raw_message);
		//verify DS
		try {
			Signature sig = Signature.getInstance("MD5WithRSA");
			PublicKey senderIdentity  = KeyFactory.getInstance("RSA").generatePublic(
					new X509EncodedKeySpec(senderPublicKey)); 
			sig.initVerify(senderIdentity);
			sig.update(raw_message);
			if (sig.verify(ds)) {
				System.out.println("Sender identity verified");
			} else {
				System.out.println("Sender identity mismatch");
			}
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	public byte[] toBytes(String privateKey) {
		ByteBuffer buffer = ByteBuffer.allocate(MAX_SIZE);
		System.out.println("start " + buffer.position());
		buffer.put((byte) 1);
		System.out.println("sender " + buffer.position());
		buffer.put(Base64.decodeBase64(sender));
		System.out.println("recipient " + buffer.position());
		buffer.put(Base64.decodeBase64(recipient));
		System.out.println("message ID " + buffer.position());
		buffer.put(OisemsMessage.stringToBytesASCII(messageId));
		System.out.println("timestamp " + buffer.position());
		buffer.putLong(timestamp);
		System.out.println("part " + buffer.position());
		buffer.putInt(part);
		System.out.println("ds " + buffer.position());
		try {
			Signature sig;
			sig = Signature.getInstance("MD5WithRSA");
			PKCS8EncodedKeySpec kspec = new PKCS8EncodedKeySpec(
					Base64.decodeBase64(privateKey));
			KeyFactory kf = KeyFactory.getInstance("RSA");
			PrivateKey privKey = kf.generatePrivate(kspec);
			sig.initSign(privKey);
			byte[] payload = getMessagePayload();
			sig.update(payload);
			System.out.println("sig position = " + buffer.position());
			buffer.put(sig.sign());
			System.out.println("sig position = " + buffer.position());
			buffer.put(payload);
			return buffer.array();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	public static byte[] stringToBytesASCII(String str) {
		char[] buffer = str.toCharArray();
		byte[] b = new byte[buffer.length];
		for (int i = 0; i < b.length; i++) {
			b[i] = (byte) buffer[i];
		}
		return b;
	}

	public String toHexString(String privateKey) {
		final char[] hexArray = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
				'9', 'A', 'B', 'C', 'D', 'E', 'F' };
		byte[] bytes = toBytes(privateKey);
		char[] hexChars = new char[bytes.length * 2];
		int v;
		for (int j = 0; j < bytes.length; j++) {
			v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}

}
