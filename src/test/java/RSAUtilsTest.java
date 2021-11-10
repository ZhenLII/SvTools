import org.junit.Assert;
import org.junit.Test;
import sun.nio.cs.UTF_8;

import java.io.IOException;
import java.security.*;

/**
 * @author JiangSenwei
 */
public class RSAUtilsTest {

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
        byte[] plainBytes = plainText.getBytes(UTF_8.INSTANCE);
        try {
            String cipherText = RSAUtils.encryptToBase64(plainText, keyPair.getPublic());
            byte[] cipherBytes = RSAUtils.encryptToBytes(plainText, keyPair.getPublic());

            String strAfterDecript = RSAUtils.decryptToStringFromBase64(cipherText, keyPair.getPrivate());
            byte[] bytesAfterDecript1 = RSAUtils.decryptToBytesFromBase64(cipherText, keyPair.getPrivate());
            byte[] bytesAfterDecript2 = RSAUtils.decryptToBytesFromBytes(cipherBytes, keyPair.getPrivate());

            Assert.assertEquals(plainText, strAfterDecript);
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
