package me.yimu.demo.encrypt;

import android.app.Application;

/**
 * Created by linwei on 2018/1/2.
 */

public class MyApplication extends Application {

    @Override
    public void onCreate() {
        super.onCreate();
        _GetEncryptedKey.get(this);
        Api.get().init(this);
    }
}
