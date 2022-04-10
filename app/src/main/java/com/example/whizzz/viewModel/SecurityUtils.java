package com.example.whizzz.viewModel;

import android.content.Context;
import android.preference.PreferenceManager;
import android.util.Base64;


import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;


public class SecurityUtils {
    public static String encryptMessage(String publicKeyString, String plainText) {
        return null;
    }

    public static String encryptKey(String publicKeyString, String plainText) {
        byte[] publicKeyBytes = Base64.decode(publicKeyString, Base64.DEFAULT);
        String cipherText = null;
        try {
            Key publicKey = loadPublicRSAKey(publicKeyBytes);
            Cipher encryptCipher = Cipher.getInstance("RSA");
            encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] cipherTextBytes = encryptCipher.doFinal(plainText.getBytes());
            cipherText = Base64.encodeToString(cipherTextBytes, Base64.NO_WRAP | Base64.NO_PADDING);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        return cipherText;
    }

    public static String decryptMessage(Context context, String cipherText) {
        byte[] privateKeyBytes = Base64.decode(PreferenceManager.getDefaultSharedPreferences(context).getString("private_key", null), Base64.DEFAULT);
        String plainText = "";
        try {
            Key privateKey = loadPrivateRSAKey(privateKeyBytes);
            Cipher decryptCipher = Cipher.getInstance("RSA");
            decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] cipherTextBytes = Base64.decode(cipherText, Base64.NO_WRAP);
            plainText = new String(decryptCipher.doFinal(cipherTextBytes), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }


        return plainText;
//        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

//        keyFactory.generatePublic(publicKeySpec);
    }

    public static Key loadPrivateRSAKey(byte[] stored) throws GeneralSecurityException {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(stored);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(keySpec);
    }

    public static Key loadPublicRSAKey(byte[] stored) throws GeneralSecurityException {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(stored);
        KeyFactory fact = KeyFactory.getInstance("RSA");
        return fact.generatePublic(spec);
    }

    public static SecretKey generateAESKey(int n) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(n);
        SecretKey key = keyGenerator.generateKey();
        return key;
    }
}
