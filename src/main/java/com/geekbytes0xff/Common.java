package com.geekbytes0xff;

import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jwt.JwtClaims;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Arrays;
import java.util.List;

public class Common {

    public static JwtClaims getSampleJWT() {
        JwtClaims claims = new JwtClaims();
        claims.setAudience("Admins");
        claims.setExpirationTimeMinutesInTheFuture(10); //10 minutes from now
        claims.setGeneratedJwtId();
        claims.setIssuer("CA");
        claims.setIssuedAtToNow();
        claims.setNotBeforeMinutesInThePast(2);
        claims.setSubject("100bytesAdmin");

        claims.setClaim("email", "<a href=\"mailto:100bytesAdmin@100bytes.com\">100bytesAdmin@100bytes.com</a>");
        claims.setClaim("Country", "Antartica");
        List hobbies = Arrays.asList("Blogging", "Playing cards", "Games");
        claims.setStringListClaim("hobbies", hobbies);
        return claims;
    }

    public final RsaJsonWebKey receiversAsymetricKey;

    public Common() throws Exception {
        receiversAsymetricKey = RsaJwkGenerator.generateJwk(2048);
    }

    public static SecretKey generateKey(String alg, int bitsLength) throws Exception{
        KeyGenerator keyGenerator = KeyGenerator.getInstance(alg);
        keyGenerator.init(bitsLength);
        SecretKey contentEncryptKey = keyGenerator.generateKey();
        return contentEncryptKey;
    }


}
