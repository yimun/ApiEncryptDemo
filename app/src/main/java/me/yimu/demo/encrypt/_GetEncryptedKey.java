package me.yimu.demo.encrypt;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.util.Base64;
import android.util.Log;

/**
 * Created by linwei on 2018/1/2.
 */

public class _GetEncryptedKey {

    static final String TAG = "_GetEncryptedKey";

    public static void get(Context context) {
        try {
            // 获取apk签名做密钥
            PackageInfo packageInfo = context.getPackageManager().getPackageInfo(
                    context.getPackageName(), PackageManager.GET_SIGNATURES);
            String password = Base64.encodeToString(packageInfo.signatures[0].toByteArray(),
                    Base64.DEFAULT);
            // 用签名解密出api key
            Log.d(TAG, "Encrypted apikey=" + AES.encrypt("thisisapikey", password));
            // G6t3IHRvM6GQ28RZ3RFojQ==
            Log.d(TAG, "Encrypted apisecret=" + AES.encrypt("thisisapisecret", password));
            // vtZn+Kmt+wK4zy9xSjrlqg==
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
        }
    }
}
