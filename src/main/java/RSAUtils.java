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
    public final static String SHA256withRSA = "SHA256withRSA";

    /**
     * 随机生成RSA秘钥对
     *
     * @return RSA 秘钥对对象
     */
    public static KeyPair generate2048SizeKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(RSA);
        generator.initialize(2048, new SecureRandom());
        return generator.generateKeyPair();
    }


    /**
     * 从bytes中读取RSA公钥和私钥返回秘钥对对象
     *
     * @param pubKey 公钥二进制数据
     * @param priKey 私钥二进制数据
     * @return RSA 秘钥对对象
     */
    public static KeyPair readKeyPair(byte[] pubKey, byte[] priKey) throws GeneralSecurityException {
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubKey);
        PKCS8EncodedKeySpec priSpec = new PKCS8EncodedKeySpec(priKey);
        return new KeyPair(keyFactory.generatePublic(pubSpec), keyFactory.generatePrivate(priSpec));
    }

    /**
     * 使用公钥将明文字符串加密，以Base64格式返回
     *
     * @param plainText 被加密的明文字符串
     * @param publicKey 用于加密的公钥
     * @return 加密后采用Base64编码的字符串
     */
    public static String encryptToBase64(String plainText, PublicKey publicKey) throws GeneralSecurityException {
        Cipher encryptCipher = Cipher.getInstance(RSA);
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(UTF_8.INSTANCE));
        return Base64.getEncoder().encodeToString(cipherText);
    }

    /**
     * 使用公钥将明文字符串加密，返回加密后的二进制数据
     *
     * @param plainText 被加密的明文字符串
     * @param publicKey 用于加密的公钥
     * @return 加密后的二进制数据
     */
    public static byte[] encryptToBytes(String plainText, PublicKey publicKey) throws GeneralSecurityException {
        Cipher encryptCipher = Cipher.getInstance(RSA);
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return encryptCipher.doFinal(plainText.getBytes(UTF_8.INSTANCE));
    }

    /**
     * 使用私钥将Base64编码的密文字符串解密，返回解密后的字符串
     *
     * @param cipherText 加密后的密文，采用Base64编码
     * @param privateKey 用于解密的私钥
     * @return 解密后的明文字符串
     */
    public static String decryptToStringFromBase64(String cipherText, PrivateKey privateKey) throws GeneralSecurityException {
        byte[] bytes = Base64.getDecoder().decode(cipherText);
        Cipher decriptCipher = Cipher.getInstance(RSA);
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(decriptCipher.doFinal(bytes), UTF_8.INSTANCE);
    }

    /**
     * 使用私钥将二进制的密文字符串解密，返回解密后的字符串
     *
     * @param cipherText 加密后的密文，二进制格式
     * @param privateKey 用于解密的私钥
     * @return 解密后的明文字符串
     */
    public static String decryptToStringFromBytes(byte[] cipherText, PrivateKey privateKey) throws GeneralSecurityException {
        Cipher decriptCipher = Cipher.getInstance(RSA);
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(decriptCipher.doFinal(cipherText), UTF_8.INSTANCE);
    }

    /**
     * 使用私钥将Base64编码的密文字符串解密，返回解密后的二进制数据
     *
     * @param cipherText 加密后的密文，采用Base64编码
     * @param privateKey 用于解密的私钥
     * @return 解密后的二进制数据
     */
    public static byte[] decryptToBytesFromBase64(String cipherText, PrivateKey privateKey) throws GeneralSecurityException {
        byte[] bytes = Base64.getDecoder().decode(cipherText);
        Cipher decriptCipher = Cipher.getInstance(RSA);
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        return decriptCipher.doFinal(bytes);
    }

    /**
     * 使用私钥将二进制的密文字符串解密，返回解密后的二进制数据
     *
     * @param cipherText 加密后的密文，二进制数据
     * @param privateKey 用于解密的私钥
     * @return 解密后的二进制数据
     */
    public static byte[] decryptToBytesFromBytes(byte[] cipherText, PrivateKey privateKey) throws GeneralSecurityException {
        Cipher decriptCipher = Cipher.getInstance(RSA);
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        return decriptCipher.doFinal(cipherText);
    }


    /**
     * 使用私钥签名明文，返回Base64格式的签名字符串
     *
     * @param plainText 用于签名的明文
     * @param privateKey 用于签名的私钥
     * @return Base64格式的签名字符串
     */
    public static String sign(String plainText, PrivateKey privateKey) throws GeneralSecurityException {
        Signature privateSignature = Signature.getInstance(SHA256withRSA);
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes(UTF_8.INSTANCE));
        byte[] signature = privateSignature.sign();
        return Base64.getEncoder().encodeToString(signature);
    }

    /**
     * 使用公钥和明文校验签名
     *
     * @param plainText 用于验证签名的明文
     * @param signature Base64格式的签名
     * @param publicKey 用于验证签名的公钥
     * @return 签名验证是否通过
     */
    public static boolean verify(String plainText, String signature, PublicKey publicKey) throws GeneralSecurityException {
        Signature publicSignature = Signature.getInstance(SHA256withRSA);
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes(UTF_8.INSTANCE));
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return publicSignature.verify(signatureBytes);
    }
}
