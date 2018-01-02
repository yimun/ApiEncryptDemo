package me.yimu.demo.encrypt;

import android.util.Base64;
import android.util.Log;

import java.io.UnsupportedEncodingException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by linwei on 2018/1/2.
 */

public class AES {

    private static final String IV = "CUSTOMGIVEDAPPIV";

    /**
     * Encrypt string to string with password
     *
     * @param rawData
     * @param password
     * @return
     */
    public static final String encrypt(String rawData, String password) {
        try {
            SecretKeySpec key = generateKey(password);
            byte[] result = doEncrypt(key, rawData.getBytes());
            return Base64.encodeToString(result, Base64.DEFAULT);
        } catch (Exception e) {
            return rawData;
        }
    }

    public static final String decrypt(String cipherData, String password) {
        try {
            SecretKeySpec key = generateKey(password);
            byte[] enc = Base64.decode(cipherData, Base64.DEFAULT);
            byte[] result = doDecrypt(key, enc);
            return new String(result);
        } catch (Exception e) {
            Log.i("xxx", e.getMessage());
            return cipherData;
        }
    }

    /**
     * @param password
     * @return
     * @throws Exception
     */
    private static SecretKeySpec generateKey(String password) throws Exception {
        byte[] data = null;
        if (password == null) {
            password = "";
        }
        StringBuffer sb = new StringBuffer(16);
        sb.append(password);
        while (sb.length() < 16) {
            sb.append("\0");
        }
        if (sb.length() > 16) {
            sb.setLength(16);
        }
        try {
            data = sb.toString().getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return new SecretKeySpec(data, "AES");
    }


    /**
     * AES  加密
     *
     * @param key   AES 加密的KEY
     * @param clear AES 加密的内容 （128位的明文）
     * @return 返回 128位的密文
     * @throws Exception
     */
    private static byte[] doEncrypt(SecretKeySpec key, byte[] clear) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivspec = new IvParameterSpec(IV.getBytes());
        cipher.init(Cipher.ENCRYPT_MODE, key, ivspec);
        return cipher.doFinal(clear);
    }

    /**
     * AES  解密
     *
     * @param key       AES 解密的KEY
     * @param encrypted AES 解密的内容 （128位的密文）
     * @return 返回 （128位的明文）
     * @throws Exception
     */
    private static byte[] doDecrypt(SecretKeySpec key, byte[] encrypted) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivspec = new IvParameterSpec(IV.getBytes());
        cipher.init(Cipher.DECRYPT_MODE, key, ivspec);
        return cipher.doFinal(encrypted);
    }
}
