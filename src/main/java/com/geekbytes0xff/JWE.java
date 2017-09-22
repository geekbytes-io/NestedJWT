package com.geekbytes0xff;

import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;

import javax.crypto.SecretKey;
import java.security.SecureRandom;

public class JWE {

    public static byte[] generateJWEInitializationVector() throws Exception {
        SecureRandom iv = SecureRandom.getInstance("SHA1PRNG");
        return iv.generateSeed(16);
    }


    public static void main(String[] args) throws Exception {

        Common common = new Common();

        JwtClaims claims = Common.getSampleJWT();

        SecretKey contentEncryptKey = Common.generateKey("AES", 256);

        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setKey(common.receiversAsymetricKey.getPublicKey());
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP_256);
        jwe.setContentEncryptionKey(contentEncryptKey.getEncoded());
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        jwe.setIv(generateJWEInitializationVector());
        jwe.setPayload(claims.toJson());
        String encryptedJwt = jwe.getCompactSerialization();
        System.out.println("Encrypted ::" + encryptedJwt);
    }
}
