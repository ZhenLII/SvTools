import sun.nio.cs.UTF_8;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * @author JiangSenwei
 */
public class RSAUtils {
    public final static String RSA = "RSA";
    public final static String SHA256withRSA="SHA256withRSA";

    public static KeyPair generate2048SizeKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(RSA);
        generator.initialize(2048, new SecureRandom());
        return generator.generateKeyPair();
    }

    public static KeyPair readKeyPair(byte[] pubKey, byte[] priKey) throws GeneralSecurityException {
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubKey);
        PKCS8EncodedKeySpec priSpec = new PKCS8EncodedKeySpec(priKey);
        return new KeyPair(keyFactory.generatePublic(pubSpec),keyFactory.generatePrivate(priSpec));
    }

    public static String encryptToBase64(String plainText, PublicKey publicKey) throws GeneralSecurityException {
        Cipher encryptCipher = Cipher.getInstance(RSA);
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(UTF_8.INSTANCE));
        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static byte[] encryptToBytes(String plainText, PublicKey publicKey) throws GeneralSecurityException {
        Cipher encryptCipher = Cipher.getInstance(RSA);
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return encryptCipher.doFinal(plainText.getBytes(UTF_8.INSTANCE));
    }

    public static String decryptToStringFromBase64(String cipherText, PrivateKey privateKey) throws GeneralSecurityException {
        byte[] bytes = Base64.getDecoder().decode(cipherText);
        Cipher decriptCipher = Cipher.getInstance(RSA);
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(decriptCipher.doFinal(bytes), UTF_8.INSTANCE);
    }

    public static byte[] decryptToBytesFromBase64(String cipherText, PrivateKey privateKey) throws GeneralSecurityException {
        byte[] bytes = Base64.getDecoder().decode(cipherText);
        Cipher decriptCipher = Cipher.getInstance(RSA);
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        return decriptCipher.doFinal(bytes);
    }

    public static byte[] decryptToBytesFromBytes(byte[] cipherText, PrivateKey privateKey) throws GeneralSecurityException {
        Cipher decriptCipher = Cipher.getInstance(RSA);
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        return decriptCipher.doFinal(cipherText);
    }

    public static String sign(String plainText, PrivateKey privateKey) throws GeneralSecurityException  {
        Signature privateSignature = Signature.getInstance(SHA256withRSA);
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes(UTF_8.INSTANCE));
        byte[] signature = privateSignature.sign();
        return Base64.getEncoder().encodeToString(signature);
    }

    public static boolean verify(String plainText, String signature, PublicKey publicKey) throws GeneralSecurityException {
        Signature publicSignature = Signature.getInstance(SHA256withRSA);
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes(UTF_8.INSTANCE));
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return publicSignature.verify(signatureBytes);
    }
}
