
import javax.crypto.Cipher;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
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
    public final static int CYPHER_LENGTH = 2048;
    public final static int TEXT_BLOCK_SIZE = 128;
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
    public static void generate2048PriKeyToPem(Path path) throws Exception {
        KeyPair keyPair = generate2048SizeKeyPair();
        savePriKeyToPem(path, keyPair.getPrivate());
    }

    /**
     * 保存私钥到指定pem文件中
     */
    public static void savePriKeyToPem(Path pemPath, PrivateKey privateKey) throws Exception {
        File pemFile;
        if (pemPath == null) {
            throw new Exception("File Can Not Be <null>");
        }
        pemFile = pemPath.toFile();

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
    public static void savePubKeyToPem(Path pemPath, PublicKey publicKey) throws Exception {
        File pemFile;
        if (pemPath == null) {
            throw new Exception("File Can Not Be <null>");
        }
        pemFile = pemPath.toFile();
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
        generator.initialize(CYPHER_LENGTH, new SecureRandom());
        return generator.generateKeyPair();
    }

    /**
     * 从pem文件中读取RSA私钥对象，并计算出公钥，返回秘钥对
     *
     * @param path     私钥pem文件路径
     * @param exponent 计算公钥的指数值，默认为0x010001 (65537)
     * @return RSA 秘钥对对象
     */
    public static KeyPair readKeyPairFromPem(Path path, BigInteger exponent) throws Exception {
        File pemFile;
        if (path == null || !(pemFile = path.toFile()).exists() || pemFile.isDirectory()) {
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
     * 使用公钥将明文二进制数据加密，返回加密后的二进制数据
     * 如果明文长度大于秘钥长度，将会以 128byte大小 分块加密，要求秘钥长度必须大于2048bit(256byte)
     *
     * @param textBytes 需要被加密的明文字符串
     * @param publicKey 用于加密的公钥
     * @return 加密后的二进制数据
     */
    public static byte[] encrypt(byte[] textBytes, PublicKey publicKey) throws Exception {
        int bitLength = checkPublicKey(publicKey);
        int cipherBlockSize = bitLength / 8;
        int cipherLength = ((textBytes.length / TEXT_BLOCK_SIZE) + 1) * cipherBlockSize;
        byte[] cipherBytes = new byte[cipherLength];
        Cipher encryptCipher = Cipher.getInstance(RSA);
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        if (textBytes.length > TEXT_BLOCK_SIZE) {
            int times;
            int plainIndex = 0;
            int cipherIndex = 0;
            for (times = 0; times < textBytes.length / TEXT_BLOCK_SIZE; times++) {
                byte[] tmp = new byte[TEXT_BLOCK_SIZE];
                System.arraycopy(textBytes, plainIndex, tmp, 0, TEXT_BLOCK_SIZE);
                byte[] cipherTmp = encryptCipher.doFinal(tmp);
                System.arraycopy(cipherTmp, 0, cipherBytes, cipherIndex, cipherBlockSize);
                plainIndex += TEXT_BLOCK_SIZE;
                cipherIndex += cipherBlockSize;
            }
            byte[] tmp = new byte[textBytes.length - plainIndex];
            System.arraycopy(textBytes, plainIndex, tmp, 0, textBytes.length - plainIndex);
            byte[] cipherTmp = encryptCipher.doFinal(tmp);
            System.arraycopy(cipherTmp, 0, cipherBytes, cipherIndex, cipherBlockSize);
        } else {
            cipherBytes = encryptCipher.doFinal(textBytes);
        }
        return cipherBytes;
    }


    /**
     * 使用公钥将明文字符串加密，以Base64格式返回
     *
     * @param plainText 被加密的明文字符串
     * @param publicKey 用于加密的公钥
     * @return 加密后采用Base64编码的字符串
     */
    public static String encryptToBase64(String plainText, PublicKey publicKey) throws Exception {
        byte[] textBytes = plainText.getBytes(StandardCharsets.UTF_8);
        return Base64.getEncoder().encodeToString(encrypt(textBytes, publicKey));
    }

    /**
     * 使用公钥将明文字符串加密，返回加密后的二进制数据
     *
     * @param plainText 被加密的明文字符串
     * @param publicKey 用于加密的公钥
     * @return 加密后的二进制数据
     */
    public static byte[] encryptToBytes(String plainText, PublicKey publicKey) throws Exception {
        byte[] textBytes = plainText.getBytes(StandardCharsets.UTF_8);
        return encrypt(textBytes, publicKey);
    }


    /**
     * 使用私钥将二进制的密文字符串解密，返回解密后的二进制数据
     *
     * @param cipherBytes 加密后的密文，二进制数据
     * @param privateKey  用于解密的私钥
     * @return 解密后的二进制数据
     */
    public static byte[] decrypt(byte[] cipherBytes, PrivateKey privateKey) throws Exception {
        int bitLength = checkPrivateKey(privateKey);
        int cipherBlockSize = bitLength / 8;
        if (cipherBytes.length % cipherBlockSize != 0) {
            throw new Exception("Encrypted Data Length Error. Must be an integer multiple of the cypher length.");
        }
        Cipher decriptCipher = Cipher.getInstance(RSA);
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] plainBytes;
        if (cipherBytes.length / cipherBlockSize > 1) {
            int cipherIndex = 0;
            int times;
            plainBytes = new byte[0];
            for (times = 0; times < cipherBytes.length / cipherBlockSize; times++) {
                byte[] tmp = new byte[cipherBlockSize];
                System.arraycopy(cipherBytes, cipherIndex, tmp, 0, cipherBlockSize);
                byte[] plainTmp = decriptCipher.doFinal(tmp);
                byte[] newPlainBytes = new byte[plainBytes.length + plainTmp.length];
                System.arraycopy(plainBytes, 0, newPlainBytes, 0, plainBytes.length);
                System.arraycopy(plainTmp, 0, newPlainBytes, plainBytes.length, plainTmp.length);
                plainBytes = newPlainBytes;
                cipherIndex += cipherBlockSize;
            }
        } else {
            plainBytes = decriptCipher.doFinal(cipherBytes);
        }

        return plainBytes;
    }

    /**
     * 使用私钥将Base64编码的密文字符串解密，返回解密后的字符串
     *
     * @param cipherText 加密后的密文，采用Base64编码
     * @param privateKey 用于解密的私钥
     * @return 解密后的明文字符串
     */
    public static String decryptToStringFromBase64(String cipherText, PrivateKey privateKey) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(cipherText);
        return new String(decrypt(bytes, privateKey), StandardCharsets.UTF_8);
    }

    /**
     * 使用私钥将二进制的密文字符串解密，返回解密后的字符串
     *
     * @param cipherText 加密后的密文，二进制格式
     * @param privateKey 用于解密的私钥
     * @return 解密后的明文字符串
     */
    public static String decryptToStringFromBytes(byte[] cipherText, PrivateKey privateKey) throws Exception {
        return new String(decrypt(cipherText, privateKey), StandardCharsets.UTF_8);
    }

    /**
     * 使用私钥将Base64编码的密文字符串解密，返回解密后的二进制数据
     *
     * @param cipherText 加密后的密文，采用Base64编码
     * @param privateKey 用于解密的私钥
     * @return 解密后的二进制数据
     */
    public static byte[] decryptToBytesFromBase64(String cipherText, PrivateKey privateKey) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(cipherText);
        return decrypt(bytes, privateKey);
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

    private static int checkPrivateKey(PrivateKey privateKey) throws Exception {
        if (!(privateKey instanceof RSAPrivateKey)) {
            throw new Exception("Private Key Must be RSA Private Key");
        }
        int bitLength = ((RSAPrivateKey) privateKey).getModulus().bitLength();
        if (bitLength < CYPHER_LENGTH) {
            throw new Exception("RSA Key Length Is Too Short. At Least 2048 bits.");
        }
        return bitLength;
    }

    private static int checkPublicKey(PublicKey publicKey) throws Exception {
        if (!(publicKey instanceof RSAPublicKey)) {
            throw new Exception("Public Key Must be RSA Public Key");
        }
        int bitLength = ((RSAPublicKey) publicKey).getModulus().bitLength();
        if (bitLength < CYPHER_LENGTH) {
            throw new Exception("RSA Key Length Is Too Short. At Least 2048 bits.");
        }
        return bitLength;
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
