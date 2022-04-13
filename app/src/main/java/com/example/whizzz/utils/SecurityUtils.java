package com.example.whizzz.utils;

import android.content.Context;
import android.preference.PreferenceManager;
import android.util.Base64;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class SecurityUtils {
    public static final String AES_CIPHER = "AES/CBC/PKCS5Padding";
    public static final String RSA_CIPHER = "RSA";
    public static final int AES_KEY_LENGTH = 256;

    public static String encryptMessage(String symmetricKey, String plainText) {
        byte[] symmetricKeyBytes = keyBytesFromString(symmetricKey);

        String cipherText = null;
        String ivString = null;
        try {
            SecretKeySpec secretKey = new SecretKeySpec(symmetricKeyBytes, "AES");
            Cipher cipher = Cipher.getInstance(AES_CIPHER);

            SecureRandom randomSecureRandom = new SecureRandom();
            byte[] iv = new byte[cipher.getBlockSize()];
            randomSecureRandom.nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
            byte[] cipherTextBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
            cipherText = Base64.encodeToString(cipherTextBytes, Base64.DEFAULT);
            ivString = Base64.encodeToString(iv, Base64.DEFAULT);
        } catch (InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return String.format("%s,%s", ivString, cipherText);
    }

    public static String decryptMessage(String symmetricKey, String ivAndCipher) {
        String ivString = ivAndCipher.split(",")[0];
        String cipherText = ivAndCipher.split(",")[1];
        byte[] iv = Base64.decode(ivString, Base64.DEFAULT);
        byte[] cipherTextBytes = Base64.decode(cipherText, Base64.DEFAULT);
        byte[] symmetricKeyBytes = keyBytesFromString(symmetricKey);

        SecretKeySpec secretKey = new SecretKeySpec(symmetricKeyBytes, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        String plainText = null;
        try {
            Cipher cipher = Cipher.getInstance(AES_CIPHER);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
            byte[] plainTextBytes = cipher.doFinal(cipherTextBytes);
            plainText = new String(plainTextBytes);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException e) {
            e.printStackTrace();
        }
        return plainText;
    }

    public static String encryptSymmetricKey(String publicKeyString, String plainTextSymmetricKey) {
        byte[] publicKeyBytes = keyBytesFromString(publicKeyString);
        String cipherText = null;
        try {
            Key publicKey = loadPublicRSAKey(publicKeyBytes);
            Cipher encryptCipher = Cipher.getInstance(RSA_CIPHER);
            encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] cipherTextBytes = encryptCipher.doFinal(Base64.decode(plainTextSymmetricKey.getBytes(), Base64.DEFAULT));
            cipherText = Base64.encodeToString(cipherTextBytes, Base64.DEFAULT);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        return cipherText;
    }

    public static String decryptSymmetricKey(Context context, String cipherTextSymmetricKey) {
        byte[] privateKeyBytes = Base64.decode(PreferenceManager.getDefaultSharedPreferences(context).getString("private_key", null), Base64.DEFAULT);
        String plainText = "";
        try {
            Key privateKey = loadPrivateRSAKey(privateKeyBytes);
            Cipher decryptCipher = Cipher.getInstance(RSA_CIPHER);
            decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] cipherTextBytes = Base64.decode(cipherTextSymmetricKey, Base64.DEFAULT);
            plainText = Base64.encodeToString(decryptCipher.doFinal(cipherTextBytes), Base64.DEFAULT);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }


        return plainText;
//        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

//        keyFactory.generatePublic(publicKeySpec);
    }

    public static Key loadPrivateRSAKey(byte[] stored) throws GeneralSecurityException {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(stored);
        KeyFactory kf = KeyFactory.getInstance(RSA_CIPHER);
        return kf.generatePrivate(keySpec);
    }

    public static Key loadPublicRSAKey(byte[] stored) throws GeneralSecurityException {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(stored);
        KeyFactory fact = KeyFactory.getInstance(RSA_CIPHER);
        return fact.generatePublic(spec);
    }

    public static SecretKey generateAESKey() {
        KeyGenerator keyGenerator = null;
        try {
            keyGenerator = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        keyGenerator.init(AES_KEY_LENGTH);
        SecretKey key = keyGenerator.generateKey();
        return key;
    }

    public static String keyToString(Key key) {
        return Base64.encodeToString(key.getEncoded(), Base64.DEFAULT);
    }

    public static byte[] keyBytesFromString(String string) {
        return Base64.decode(string, Base64.DEFAULT);
    }
}
