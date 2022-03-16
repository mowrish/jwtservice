import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Date;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public class JWTCreation {

	public static void main(String[] args)
			throws JOSEException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		String filePath = "";
		String alias = "";
		String password = "";
		String issuer = "";
		createJwt(filePath, alias, password, issuer);
	}

	private static void createJwt(String filePath, String alias, String password, String issuer)
			throws KeyStoreException, JOSEException, NoSuchAlgorithmException, CertificateException, IOException {
		
		InputStream inputStream = new FileInputStream(new File(filePath));
		char[] pin = password.toCharArray();
		KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
		keystore.load(inputStream, pin);
		RSAKey rsaJWK = RSAKey.load(keystore, alias, pin);
		JWSSigner signer = new RSASSASigner(rsaJWK);

		Date currentTime = new Date();

		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS512)
				.type(JOSEObjectType.JWT)
				.build();
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
				.issuer(issuer)
				.issueTime(currentTime)
				.expirationTime(new Date(currentTime.getTime() + 60 * 1000)).build();

		SignedJWT jwt = new SignedJWT(header, claimsSet);
		jwt.sign(signer);
		String serializedJWT = jwt.serialize();

		System.out.println(serializedJWT);
		
	}

}
