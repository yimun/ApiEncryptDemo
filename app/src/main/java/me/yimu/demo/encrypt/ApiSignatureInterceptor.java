package me.yimu.demo.encrypt;

import android.net.Uri;
import android.text.TextUtils;
import android.util.Log;
import android.util.Pair;

import java.io.IOException;

import okhttp3.FormBody;
import okhttp3.HttpUrl;
import okhttp3.Interceptor;
import okhttp3.MultipartBody;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

/**
 * Created by linwei on 2018/1/2.
 */

public class ApiSignatureInterceptor implements Interceptor {

    private static final String TAG = "ApiSignatureInterceptor";

    /**
     * Header中的Authorization字符串前缀
     */
    private static final String OAUTH_PREFIX = "Bearer ";

    /**
     * 签名
     */
    private static final String KEY_SIG = "_sig";

    /**
     * 时间
     */
    private static final String KEY_TIME = "_ts";

    @Override
    public Response intercept(Chain chain) throws IOException {
        Request request = chain.request();
        // 添加用户认证
        request = addAuth(request);

        // 添加签名信息
        if (null != request) {
            String method = request.method();
            // GET 请求
            if (TextUtils.equals(method, Http.METHOD_GET)) {
                request = signGetRequest(request);
            } else {
                RequestBody requestBody = request.body();
                if (null != requestBody && requestBody instanceof FormBody) {
                    // FORM 请求
                    request = signFormRequest(request);
                } else if (null != requestBody && requestBody instanceof MultipartBody) {
                    // MULTIPART 请求
                    request = signMultiPartRequest(request);
                }
            }
        }
        return chain.proceed(request);
    }

    /**
     * 添加用户认证信息，如token，apiKey
     * @param request
     * @return
     */
    private Request addAuth(Request request) {
        HttpUrl httpUrl = request.url();
        httpUrl = httpUrl.newBuilder()
                .setQueryParameter("apkey", Api.get().apiKey())
                .build();
        return request.newBuilder().url(httpUrl)
                .addHeader(Http.HEADER_AUTHORIZATION, OAUTH_PREFIX + Session.getToken())
                .build();
    }

    /**
     * GET 请求签名
     *
     * @param request
     * @return
     */
    private Request signGetRequest(Request request) {
        Pair<String, String> signature = getRequestSignature(request);
        if (null == signature) {
            return request;
        }
        Log.i(TAG, "resign get: " + request.url().toString());
        HttpUrl httpUrl = request.url();
        httpUrl = httpUrl.newBuilder().setQueryParameter(KEY_SIG, signature.first)
                .setQueryParameter(KEY_TIME, signature.second)
                .build();
        return request.newBuilder().url(httpUrl).build();
    }

    /**
     * FORM 请求签名
     *
     * @param request
     * @return
     */
    private Request signFormRequest(Request request) {
        Pair<String, String> signature = getRequestSignature(request);
        if (null == signature) {
            return request;
        }
        Log.i(TAG, "resign form: " + request.url().toString());
        FormBody formBody = (FormBody) request.body();
        FormBody.Builder newFormBodyBuilder = new FormBody.Builder();
        // 保留之前的参数，过滤掉签名信息
        int size = formBody.size();
        String name;
        for (int i = 0; i < size; i++) {
            name = formBody.name(i);
            if (TextUtils.equals(name, KEY_SIG) || TextUtils.equals(name, KEY_TIME)) {
                Log.i(TAG, "remove form signature");
                continue;
            }
            newFormBodyBuilder.add(formBody.name(i), formBody.value(i));
        }
        // 添加签名信息
        newFormBodyBuilder.add(KEY_SIG, signature.first);
        newFormBodyBuilder.add(KEY_TIME, signature.second);
        FormBody newBody = newFormBodyBuilder.build();
        return request.newBuilder()
                .post(newBody)
                .removeHeader(Http.HEADER_CONTENT_LENGTH)
                .header(Http.HEADER_CONTENT_LENGTH, String.valueOf(newBody.contentLength())).build();
    }

    /**
     * Multipart 请求签名
     *
     * @param request
     * @return
     */
    private Request signMultiPartRequest(Request request) {
        Pair<String, String> signature = getRequestSignature(request);
        if (null == signature) {
            return request;
        }
        Log.i(TAG, "resign multipart: " + request.url().toString());
        MultipartBody multipartBody = (MultipartBody) request.body();
        MultipartBody.Builder newMultipartBodyBuilder = new MultipartBody.Builder(multipartBody.boundary())
                .setType(multipartBody.type());
        // 保留之前的参数，过滤掉签名信息
        int size = multipartBody.size();
        for (int i = 0; i < size; i++) {
            MultipartBody.Part part = multipartBody.part(i);
            if (part.headers().get(Http.HEADER_CONTENT_DISPOSITION).contains(KEY_SIG) ||
                    part.headers().get(Http.HEADER_CONTENT_DISPOSITION).contains(KEY_TIME)) {
                Log.i(TAG, "remove multipart signature");
                continue;
            }
            newMultipartBodyBuilder.addPart(part);
        }
        // 添加签名信息
        newMultipartBodyBuilder.addFormDataPart(KEY_SIG, signature.first);
        newMultipartBodyBuilder.addFormDataPart(KEY_TIME, signature.second);
        MultipartBody newMultipartBody = newMultipartBodyBuilder.build();
        try {
            return request.newBuilder()
                    .post(newMultipartBody)
                    .removeHeader(Http.HEADER_CONTENT_LENGTH)
                    .header(Http.HEADER_CONTENT_LENGTH, String.valueOf(newMultipartBody.contentLength())).build();
        } catch (Exception e) {
            return request;
        }
    }

    /**
     * 计算签名信息
     *
     * @param request
     * @return
     */
    private Pair<String, String> getRequestSignature(Request request) {
        if (null == request) {
            return null;
        }
        String apiSecret = Api.get().apiSecret();
        if (TextUtils.isEmpty(apiSecret)) {
            return null;
        }
        final StringBuilder s = new StringBuilder();
        s.append(request.method());
        String path = request.url().encodedPath();
        if (path == null) {
            return null;
        }
        path = Uri.decode(path);
        if (path == null) {
            return null;
        }
        if (path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
        }
        s.append("&").append(Uri.encode(path));

        // 获取token
        String accessToken = request.header(Http.HEADER_AUTHORIZATION);
        if (!TextUtils.isEmpty(accessToken)) {
            accessToken = accessToken.substring(OAUTH_PREFIX.length());
        }
        if (!TextUtils.isEmpty(accessToken)) {
            s.append("&").append(accessToken);
        }
        final long timestamp = System.currentTimeMillis() / 1000;
        s.append("&").append(timestamp);
        String baseString = s.toString();
        String signature = HMACHash1.encode(apiSecret, baseString);
        return new Pair<>(signature, String.valueOf(timestamp));
    }
}
