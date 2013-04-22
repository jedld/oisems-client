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
import org.oisems.client.exception.MessageSenderNotVerifiedException;

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
			Cipher cipher = Cipher
					.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			byte[] header = stringToBytesASCII("OISEMS");
			MessageDigest md = MessageDigest.getInstance("MD5");
			byte[] salt = md.digest(Double.toString(Math.random()).getBytes());
			ByteBuffer buffer = ByteBuffer.allocate(1792);
			buffer.put(header);
			buffer.put(salt);
			System.out.println("salt size = " + salt.length);
			byte message_bytes[] = message.getBytes(Charset.forName("UTF-8")); 
			buffer.putInt(message_bytes.length);
			buffer.put(message_bytes);
			
			byte[] result = blockCipher(cipher,buffer.array(),Cipher.ENCRYPT_MODE);
			System.out.println("encrypted size = " + result.length);
			return result;
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

	private byte[] blockCipher(Cipher cipher, byte[] bytes, int mode)
			throws IllegalBlockSizeException, BadPaddingException {
		// string initialize 2 buffers.
		// scrambled will hold intermediate results
		byte[] scrambled = new byte[0];

		// toReturn will hold the total result
		byte[] toReturn = new byte[0];
		// if we encrypt we use 100 byte long blocks. Decryption requires 128
		// byte long blocks (because of RSA)
		int length = (mode == Cipher.ENCRYPT_MODE) ? 100 : 128;

		// another buffer. this one will hold the bytes that have to be modified
		// in this step
		byte[] buffer = new byte[length];

		for (int i = 0; i < bytes.length; i++) {

			// if we filled our buffer array we have our block ready for de- or
			// encryption
			if ((i > 0) && (i % length == 0)) {
				// execute the operation
				scrambled = cipher.doFinal(buffer);
				// add the result to our total result.
				toReturn = append(toReturn, scrambled);
				// here we calculate the length of the next buffer required
				int newlength = length;

				// if newlength would be longer than remaining bytes in the
				// bytes array we shorten it.
				if (i + length > bytes.length) {
					newlength = bytes.length - i;
				}
				// clean the buffer array
				buffer = new byte[newlength];
			}
			// copy byte into our buffer.
			buffer[i % length] = bytes[i];
		}

		// this step is needed if we had a trailing buffer. should only happen
		// when encrypting.
		// example: we encrypt 110 bytes. 100 bytes per run means we "forgot"
		// the last 10 bytes. they are in the buffer array
		scrambled = cipher.doFinal(buffer);

		// final step before we can return the modified data.
		toReturn = append(toReturn, scrambled);

		return toReturn;
	}

	private byte[] append(byte[] prefix, byte[] suffix) {
		byte[] toReturn = new byte[prefix.length + suffix.length];
		for (int i = 0; i < prefix.length; i++) {
			toReturn[i] = prefix[i];
		}
		for (int i = 0; i < suffix.length; i++) {
			toReturn[i + prefix.length] = suffix[i];
		}
		return toReturn;
	}

	public void fromBytes(byte message[], String privateKey) throws MessageSenderNotVerifiedException {
		ByteBuffer buffer = ByteBuffer.wrap(message);
		int version = buffer.get();
		System.out.println("OISEMS version " + version);
		byte senderPublicKey[] = new byte[162];
		byte recipientPublicKey[] = new byte[162];
		byte messageId[] = new byte[64];
		byte ds[] = new byte[128];
		
		buffer.get(senderPublicKey);
		setSender(Base64.encodeBase64String(senderPublicKey));
		buffer.get(recipientPublicKey);
		setRecipient(Base64.encodeBase64String(recipientPublicKey));
		
		buffer.get(messageId);
		setMessageId(new String(messageId, Charset.forName("UTF-8")));
		
		long timestamp = buffer.getLong();
		setTimestamp(timestamp);
		
		part = buffer.getInt();
		buffer.get(ds);
		int raw_message_length = buffer.getInt();
		byte raw_message[] = new byte[raw_message_length];
		buffer.get(raw_message);
		// verify DS
		try {
			Signature sig = Signature.getInstance("MD5WithRSA");
			PublicKey senderIdentity = KeyFactory.getInstance("RSA")
					.generatePublic(new X509EncodedKeySpec(senderPublicKey));
			sig.initVerify(senderIdentity);
			sig.update(raw_message);
			if (!sig.verify(ds)) {
				throw new MessageSenderNotVerifiedException();
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
		PKCS8EncodedKeySpec kspec = new PKCS8EncodedKeySpec(
				Base64.decodeBase64(privateKey));
		KeyFactory kf;
		try {
			kf = KeyFactory.getInstance("RSA");
			PrivateKey privKey = kf.generatePrivate(kspec);
			Cipher cipher = Cipher
					.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privKey);
			byte[] decrypted = blockCipher(cipher, raw_message,Cipher.DECRYPT_MODE);
			ByteBuffer messageBuffer = ByteBuffer.wrap(decrypted);
			
			byte[] header = new byte[6];
			byte[] salt = new byte[16];
			
			messageBuffer.get(header);
			messageBuffer.get(salt);

			int message_length = messageBuffer.getInt();
			byte[] decrypted_message = new byte[message_length];
			messageBuffer.get(decrypted_message,0, message_length);
			String msg = new String(decrypted_message, Charset.forName("UTF-8"));
			
			
			this.setMessage(msg);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		//Decrypt the message

	}

	public byte[] toBytes(String privateKey) {
		ByteBuffer buffer = ByteBuffer.allocate(MAX_SIZE);
		//System.out.println("start " + buffer.position());
		buffer.put((byte) 1);
		//System.out.println("sender " + buffer.position());
		buffer.put(Base64.decodeBase64(sender));
		//System.out.println("recipient " + buffer.position());
		buffer.put(Base64.decodeBase64(recipient));
		//System.out.println("message ID " + buffer.position());
		buffer.put(OisemsMessage.stringToBytesASCII(messageId));
		//System.out.println("timestamp " + buffer.position());
		buffer.putLong(timestamp);
		//System.out.println("part " + buffer.position());
		buffer.putInt(part);
		//System.out.println("ds " + buffer.position());
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
			System.out.println("payload length " + buffer.position());
			buffer.putInt(payload.length);
			System.out.println("payload start " + buffer.position());
			buffer.put(payload);
			System.out.println("end = " + buffer.position());
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
