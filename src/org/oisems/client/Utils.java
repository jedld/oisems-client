package org.oisems.client;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.codec.binary.Base64;

public class Utils {

	public static OisemsClientDevice createClientDevice() {
		KeyPairGenerator keyGen;
		try {
			keyGen = KeyPairGenerator.getInstance("RSA");
	        keyGen.initialize(512);
	        KeyPair keypair = keyGen.genKeyPair();
	        String publicKey = Base64.encodeBase64String(keypair.getPublic().getEncoded());
	        String privateKey = Base64.encodeBase64String(keypair.getPrivate().getEncoded());
	        System.out.println("rsa public key size = " + keypair.getPublic().getEncoded().length);
	        OisemsClientDevice device = new OisemsClientDevice();
	        device.setPublicKey(publicKey);
	        device.setPrivateKey(privateKey);
	        return device;
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
}
