package me.yimu.demo.encrypt;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.util.Base64;

import okhttp3.OkHttpClient;

/**
 * Created by linwei on 2018/1/2.
 */

public class Api {

    private static Api sInstance = null;

    private boolean initialized = false;

    private String mApiKey;
    private String mApiSecret;
    private OkHttpClient mClient;

    /**
     * 加密后的api key
     */
    public static final String ENCRYPTED_API_KEY = "G6t3IHRvM6GQ28RZ3RFojQ==";
    /**
     * 加密后的api secret
     */
    public static final String ENCRYPTED_API_SECRET = "vtZn+Kmt+wK4zy9xSjrlqg==";


    public static Api get() {
        if (sInstance == null) {
            synchronized (Api.class) {
                if (sInstance == null) {
                    sInstance = new Api();
                }
            }
        }
        return sInstance;
    }

    private Api() {}

    public void init(Context context) {
        initialized = true;
        initKey(context);
        initClient();
    }

    private void initKey(Context context) {
        PackageInfo packageInfo = null;
        try {
            // 获取apk签名做密钥
            packageInfo = context.getPackageManager().getPackageInfo(
                    context.getPackageName(), PackageManager.GET_SIGNATURES);
            String password = Base64.encodeToString(packageInfo.signatures[0].toByteArray(),
                    Base64.DEFAULT);
            // 用签名解密出api key
            mApiKey = AES.decrypt(ENCRYPTED_API_KEY, password);
            mApiSecret = AES.decrypt(ENCRYPTED_API_SECRET, password);
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
        }
    }

    private void initClient() {
        OkHttpClient.Builder builder = new OkHttpClient.Builder()
                .addInterceptor(new ApiSignatureInterceptor());
        mClient = builder.build();
    }

    private void assertInitialized() {
        if (!initialized) {
            throw new IllegalArgumentException("Api should call init() first");
        }
    }

    public String apiKey() {
        assertInitialized();
        return mApiKey;
    }

    public String apiSecret() {
        assertInitialized();
        return mApiSecret;
    }

    public OkHttpClient client() {
        assertInitialized();
        return mClient;
    }
}
