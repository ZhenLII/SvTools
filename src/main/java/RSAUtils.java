
import javax.crypto.Cipher;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Optional;

/**
 * @author JiangSenwei
 */
public class RSAUtils {
    public final static String RSA = "RSA";
    public final static String SHA256withRSA = "SHA256withRSA";
    public final static int MAX_SIZE = 1024 * 1024 * 32;
    public final static int DEFAULT_EXPONENT = 0x010001;

    private final static String BEGIN_PUB_KEY = "-----BEGIN PUBLIC KEY-----";
    private final static String END_PUB_KEY = "-----END PUBLIC KEY-----";
    private final static String BEGIN_RSA_PRI_KEY = "-----BEGIN RSA PRIVATE KEY-----";
    private final static String EDN_RSA_PRI_KEY = "-----BEGIN RSA PRIVATE KEY-----";
    private final static String LF = "\n";


    /**
     * 生成随机RSA秘钥对并分别保存私钥到指定pem文件中
     * 私钥中会保存modulus和exponent值，所以可以根据私钥计算出公钥
     * 故无需再保存公钥文件
     */
    public static void generate2048PriKeyToPem(File pemFile) throws Exception {
        KeyPair keyPair = generate2048SizeKeyPair();
        savePriKeyToPem(pemFile,keyPair.getPrivate());
    }

    /**
     * 保存私钥到指定pem文件中
     */
    public static void savePriKeyToPem(File pemFile,PrivateKey privateKey) throws Exception {
        if (pemFile == null) {
            throw new Exception("File Can Not Be <null>");
        }

        String base64PriKey = Base64.getEncoder().encodeToString(privateKey.getEncoded());

        String priBuilder = BEGIN_RSA_PRI_KEY + LF +
                each64byteAddLF(base64PriKey) +
                LF +
                EDN_RSA_PRI_KEY;

        Files.writeString(pemFile.toPath(), priBuilder,
                StandardOpenOption.CREATE,
                StandardOpenOption.WRITE,
                StandardOpenOption.TRUNCATE_EXISTING);

    }

    /**
     * 保存公钥到指定pem文件中
     */
    public static void savePubKeyToPem(File pemFile,PublicKey publicKey) throws Exception {
        if (pemFile == null) {
            throw new Exception("File Can Not Be <null>");
        }

        String base64PubKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());

        String priBuilder = BEGIN_PUB_KEY + LF +
                each64byteAddLF(base64PubKey) +
                LF +
                END_PUB_KEY;

        Files.writeString(pemFile.toPath(), priBuilder,
                StandardOpenOption.CREATE,
                StandardOpenOption.WRITE,
                StandardOpenOption.TRUNCATE_EXISTING);

    }


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
     * 从pem文件中读取RSA私钥对象，并计算出公钥，返回秘钥对
     *
     * @param pemFile 私钥pem文件
     * @param exponent 计算公钥的指数值，默认为0x010001 (65537)
     * @return RSA 秘钥对对象
     */
    public static KeyPair readKeyPairFromPem(File pemFile, BigInteger exponent) throws Exception {
        if (pemFile == null || !pemFile.exists() || pemFile.isDirectory()) {
            throw new Exception("File Does Not Exist");
        }
        if (pemFile.length() > MAX_SIZE) {
            throw new Exception("File Is Too Large");
        }
        if (Files.isReadable(pemFile.toPath())) {
            PrivateKey privateKey;
            PublicKey publicKey;
            KeyFactory keyFactory = KeyFactory.getInstance(RSA);
            BufferedReader reader = new BufferedReader(new FileReader(pemFile));
            StringBuilder builder = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.length() > 5 && line.substring(0, 5).equals("-----")) {
                    continue;
                }
                builder.append(line);
            }
            try {
                byte[] rawBytes = Base64.getDecoder().decode(builder.toString());
                PKCS8EncodedKeySpec priSpec = new PKCS8EncodedKeySpec(rawBytes);
                privateKey = keyFactory.generatePrivate(priSpec);
            } catch (Exception e) {
                throw new Exception("Wrong Pem File. Failed To Parse RSA Private Key");
            }
            try {
                RSAPrivateKeySpec priSpec = keyFactory.getKeySpec(privateKey, RSAPrivateKeySpec.class);
                RSAPublicKeySpec pubSpec = new RSAPublicKeySpec(priSpec.getModulus(), Optional.ofNullable(exponent).orElse(BigInteger.valueOf(DEFAULT_EXPONENT)));
                publicKey = keyFactory.generatePublic(pubSpec);
            } catch (Exception e) {
                throw new Exception("Fail To Compute Public Key");
            }
            return new KeyPair(publicKey, privateKey);
        } else {
            throw new Exception("UnReadable File");
        }
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
     * 从bytes中读取RSA公钥对象
     *
     * @param pubKey 公钥二进制数据
     * @return RSA 秘钥对对象
     */
    public static PublicKey readPublicKey(byte[] pubKey) throws GeneralSecurityException {
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubKey);
        return keyFactory.generatePublic(pubSpec);
    }

    /**
     * 从bytes中读取RSA私钥对象
     *
     * @param priKey 私钥二进制数据
     * @return RSA 秘钥对对象
     */
    public static PrivateKey readPrivateKey(byte[] priKey) throws GeneralSecurityException {
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        PKCS8EncodedKeySpec priSpec = new PKCS8EncodedKeySpec(priKey);
        return keyFactory.generatePrivate(priSpec);
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
        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
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
        return encryptCipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
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
        return new String(decriptCipher.doFinal(bytes), StandardCharsets.UTF_8);
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
        return new String(decriptCipher.doFinal(cipherText), StandardCharsets.UTF_8);
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
     * @param plainText  用于签名的明文
     * @param privateKey 用于签名的私钥
     * @return Base64格式的签名字符串
     */
    public static String sign(String plainText, PrivateKey privateKey) throws GeneralSecurityException {
        Signature privateSignature = Signature.getInstance(SHA256withRSA);
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes(StandardCharsets.UTF_8));
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
        publicSignature.update(plainText.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return publicSignature.verify(signatureBytes);
    }

    private static String each64byteAddLF(String rawString) {
        if (rawString.length() < 64) {
            return rawString;
        }
        StringBuilder builder = new StringBuilder();
        int times;
        int index = 0;
        for (times = 0; times < rawString.length() / 64; times++) {
            builder.append(rawString, index, index + 64);
            builder.append(LF);
            index += 64;
        }

        builder.append(rawString, index, rawString.length());

        return builder.toString();
    }
}
