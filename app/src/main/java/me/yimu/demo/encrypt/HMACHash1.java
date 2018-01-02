package me.yimu.demo.encrypt;

import android.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by linwei on 2018/1/2.
 */

public class HMACHash1 {


    public static final String type = "HmacSHA1";

    /**
     * hmac hash加密
     *
     * @return
     */
    public static final String encode(String secret, String baseString) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(secret.getBytes(), type);
            Mac mac = Mac.getInstance(type);
            mac.init(keySpec);
            byte[] digest = mac.doFinal(baseString.getBytes());
            return Base64.encodeToString(digest, Base64.NO_WRAP);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

}
