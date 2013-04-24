package org.oisems.client;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;

public class Utils {

	public static OisemsClientDevice createClientDevice() {
		KeyPairGenerator keyGen;
		try {
			keyGen = KeyPairGenerator.getInstance("RSA");
	        keyGen.initialize(1024);
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
	
	public static String escapeJSON(String str) {
		return "\""
				+ str.replace("\\", "\\\\").replace("\"", "\\\"")
						.replace("\n", "\\n").replace("\r", "\\r")
						.replace("\t", "\\t") + "\"";
	}

	public static String mapToJSON(Map<String, String> resultMap) {
		StringBuilder jsonString = new StringBuilder();
		jsonString.append("{");
		boolean first = true;
		for (String key : resultMap.keySet()) {
			if (!first) {
				jsonString.append(",");
			} else {
				first = false;
			}
			String value = resultMap.get(key);
			if (value == null) {
				jsonString.append("null");
			} else {
				jsonString.append(escapeJSON(key) + ":" + escapeJSON(value));
			}
		}
		jsonString.append("}");
		return jsonString.toString();
	}

	
	
}
