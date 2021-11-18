import org.junit.Assert;
import org.junit.Test;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

/**
 * @author JiangSenwei
 */
public class RSAUtilsTest {

    @Test
    public void testSaveKeyPairFile() {
        try {
            File pri = new File("pri.pem");
            File pub = new File("pub.pem");
            KeyPair keyPair = RSAUtils.generate2048SizeKeyPair();
            RSAUtils.savePriKeyToPem(pri.toPath(),keyPair.getPrivate());
            RSAUtils.savePubKeyToPem(pub.toPath(),keyPair.getPublic());
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void testReadKeyPairFileAndComputePublicKey() {
        try {
            // 这两个文件是成对的一对公钥、私钥文件
            URL priUrl = getClass().getResource("rsa_private_key.pem");
            URL pubUrl = getClass().getResource("rsa_public_key.pem");
            File priPemFile = new File(priUrl.toURI());
            File pubPemFile = new File(pubUrl.toURI());
            // 从私钥文件解析出秘钥对，使用默认指数
            KeyPair keyPair = RSAUtils.readKeyPairFromPem(priPemFile.toPath(),null);

            // 读取公钥文件
            BufferedReader reader = new BufferedReader(new FileReader(pubPemFile));
            StringBuilder builder = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.length() > 5 && line.substring(0, 5).equals("-----")) {
                    continue;
                }
                builder.append(line);
            }
            byte[] rawBytes = Base64.getDecoder().decode(builder.toString());

            // 对比从私钥中计算的公钥，和文件中的公钥
            Assert.assertArrayEquals(rawBytes, keyPair.getPublic().getEncoded());

        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void testGenerateKeyPair() {
        KeyPair keyPair;
        try {
            keyPair = RSAUtils.generate2048SizeKeyPair();
            testEncriptAndDecript(keyPair);
            testSign(keyPair);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void testReadKeyPairFromFile() {
        try {
            KeyPair keyPair = RSAUtils.readKeyPair(
                    getClass().getResourceAsStream("pub.key").readAllBytes(),
                    getClass().getResourceAsStream("pri.key").readAllBytes()
            );
            testEncriptAndDecript(keyPair);
            testSign(keyPair);
        } catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
    }


    private void testEncriptAndDecript(KeyPair keyPair) {
        String plainText = "Test Message";
        byte[] plainBytes = plainText.getBytes(StandardCharsets.UTF_8);
        try {
            String cipherText = RSAUtils.encryptToBase64(plainText, keyPair.getPublic());
            byte[] cipherBytes = RSAUtils.encryptToBytes(plainText, keyPair.getPublic());

            String strAfterDecript1 = RSAUtils.decryptToStringFromBase64(cipherText, keyPair.getPrivate());
            String strAfterDecript2 = RSAUtils.decryptToStringFromBytes(cipherBytes,keyPair.getPrivate());
            byte[] bytesAfterDecript1 = RSAUtils.decryptToBytesFromBase64(cipherText, keyPair.getPrivate());
            byte[] bytesAfterDecript2 = RSAUtils.decryptToBytesFromBytes(cipherBytes, keyPair.getPrivate());

            Assert.assertEquals(plainText, strAfterDecript1);
            Assert.assertEquals(plainText, strAfterDecript2);
            Assert.assertArrayEquals(plainBytes, bytesAfterDecript1);
            Assert.assertArrayEquals(plainBytes, bytesAfterDecript2);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
    }


    private void testSign(KeyPair keyPair) {
        String plainText = "Test Message";
        String wrongText = "Wrong Message";
        try {
            String signature = RSAUtils.sign(plainText, keyPair.getPrivate());
            Assert.assertTrue(RSAUtils.verify(plainText, signature, keyPair.getPublic()));
            Assert.assertFalse(RSAUtils.verify(wrongText, signature, keyPair.getPublic()));
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
    }

}
