package id.adrena.api.oauth.utils;

import java.io.IOException;
import java.text.ParseException;

import com.nimbusds.jose.jwk.JWKSet;

public class JWKUtils {
	
	public static JWKSet getSigningSet() throws IOException, ParseException { 
		// thowrs berguna seperti try catch dimana yg menghandle adalah fungsi sebelumnya yaitu di file endpoint blok try
		return JWKSet.load(JWKUtils.class.getResourceAsStream("/jwk/jwks.json"));
	}
	
	public static JWKSet getEncrypSet() throws IOException, ParseException {
		return JWKSet.load(JWKUtils.class.getResourceAsStream("/jwk/jwks-enc.json"));
	}
}
