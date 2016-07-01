package chapter2;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;


/**
 * Basic symmetric encryption example with padding
 */
public class SimpleSymmetricPaddingExample2
{
    public static void main(String[] args) throws Exception
    {
        byte[]        input = new byte[] {
                          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                          0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                          0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
        byte[]        keyBytes = new byte[] {
                          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                          0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                          0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };

        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");

        System.out.println("input : " + Utils.toHex(input));

        // encryption pass

        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] cipherText = cipher.doFinal(input);

        System.out.println("cipher: " + Utils.toHex(cipherText)
                                                + " bytes: " + cipherText.length);

        // decryption pass

        cipher.init(Cipher.DECRYPT_MODE, key);


        byte[] plainText = cipher.doFinal(cipherText);

        System.out.println("plain : " + Utils.toHex(plainText)
                                                + " bytes: " + plainText.length);
    }
}

