import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import sun.security.util.DerInputStream;
import sun.security.util.DerValue;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.util.Date;

public class MainExample {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, ParseException, JOSEException {
        String publicKeyContent = "-----BEGIN PUBLIC KEY-----\n" +
                "MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgHeK+z3QRFMTF24b5soc9wJs3mTe\n" +
                "IqrSuvpjnIMjEFz2Rdg3xU96y/CULaZt+CS98t6JoV+HDa9eAxfxCLslra8Nph4C\n" +
                "kQBFrLNwqB/H1KCmeCWYDtMKKlvTuWHkj2gpbqN77jyaVObenGe5r6a1wzR0ReTV\n" +
                "THrpOJ5115J80K7NAgMBAAE=\n" +
                "-----END PUBLIC KEY-----";

        String privateKeyContent = "-----BEGIN RSA PRIVATE KEY-----\n" +
                "MIICWgIBAAKBgHeK+z3QRFMTF24b5soc9wJs3mTeIqrSuvpjnIMjEFz2Rdg3xU96\n" +
                "y/CULaZt+CS98t6JoV+HDa9eAxfxCLslra8Nph4CkQBFrLNwqB/H1KCmeCWYDtMK\n" +
                "KlvTuWHkj2gpbqN77jyaVObenGe5r6a1wzR0ReTVTHrpOJ5115J80K7NAgMBAAEC\n" +
                "gYBlNocCDxPKQp/T2kvNVDjPFN43CNzRRRqKZUxeu5FfJCR+rLmiUZXaW5tLDlDK\n" +
                "ywiW4nB/MRmlITP9UVbTHVOvec0i0kfbPZ5UQ3X9C3hexT8pZG0x4pIOX1uUunkC\n" +
                "QK2lKG/KE6eR3pbSrIulbek4c+YkF0DODxkXpRtGySOVAQJBAL6Wbijx1FSHnKrI\n" +
                "Q4ErrjOcseXlA8bKwx/SZwDE95LxKWoBu2q+HwWoRymIXHdjP5VYHHbMihMnf89U\n" +
                "uU6YHL8CQQCgklwkuA9GggRPbGg6TrHLmIFo1PbBuzMyYUb3zkseGAY4zZA6lIpn\n" +
                "Fia/jV7xPdLHwa03WpCBJLlhemDWVHtzAkBsQnECyxOMjJfenvFRb2l9odWfvC4f\n" +
                "/s9FxTODSV9EVb7rm15FbQecJBGAMxgrLPJSOAG7LcaEyNwd/odgcKFrAkAYti2k\n" +
                "IQeIzF2pc3+e6ZmHQdM4tP281viMGlh3rrH00bGzcD9wJIggUVJpTHJ+IgucXnwv\n" +
                "9qoilepJzDG3Co1tAkAAuDpnUrc98/RWlICVbrJXA0WWgRl/M1GdxaA9ep2ckLGP\n" +
                "43/iIxtzO7snAUJOpD0SGUvpJnrRpJfl56EWA8xf\n" +
                "-----END RSA PRIVATE KEY-----";

        privateKeyContent = privateKeyContent.replaceAll("\\n", "").replace("-----BEGIN RSA PRIVATE KEY-----", "").replace("-----END RSA PRIVATE KEY-----", "");
        publicKeyContent = publicKeyContent.replaceAll("\\n", "").replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "");;

        KeyFactory kf = KeyFactory.getInstance("RSA");

        DerInputStream derReader = new DerInputStream(Base64.getDecoder().decode(privateKeyContent));
        DerValue[] seq = derReader.getSequence(0);

        BigInteger modulus = seq[1].getBigInteger();
        BigInteger publicExp = seq[2].getBigInteger();
        BigInteger privateExp = seq[3].getBigInteger();
        BigInteger prime1 = seq[4].getBigInteger();
        BigInteger prime2 = seq[5].getBigInteger();
        BigInteger exp1 = seq[6].getBigInteger();
        BigInteger exp2 = seq[7].getBigInteger();
        BigInteger crtCoef = seq[8].getBigInteger();

        RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(modulus, publicExp, privateExp, prime1, prime2, exp1, exp2, crtCoef);

        RSAPrivateKey privKey = (RSAPrivateKey) kf.generatePrivate(keySpec);

        X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyContent));
        RSAPublicKey pubKey = (RSAPublicKey) kf.generatePublic(keySpecX509);

        System.out.println(privKey);
        System.out.println(pubKey);

        // Create RSA-signer with the private key
        JWSSigner signer = new RSASSASigner(privKey);

        // Prepare JWT with claims set
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("alice")
                .issuer("https://c2id.com")
                .expirationTime(new Date(new Date().getTime() + 60 * 1000))
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader(JWSAlgorithm.RS256),
                claimsSet);

        // Compute the RSA signature
        signedJWT.sign(signer);

        String token = signedJWT.serialize();

        System.out.println(token);

        SignedJWT signedJWTVerifier = SignedJWT.parse(token);

        JWSVerifier verifier = new RSASSAVerifier(pubKey);

        System.out.println(signedJWTVerifier.verify(verifier));

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        PublicKey publicKey = keyPairGenerator.generateKeyPair().getPublic();

        System.out.println(new String(Base64.getEncoder().encode(pubKey.getEncoded())));

        System.out.println("================================");
        System.out.println(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
        System.out.println("================================");
    }
}
