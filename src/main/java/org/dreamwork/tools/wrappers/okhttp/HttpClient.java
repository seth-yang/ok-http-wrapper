package org.dreamwork.tools.wrappers.okhttp;

import okhttp3.*;
import org.dreamwork.gson.GsonHelper;
import org.dreamwork.util.IOUtil;
import org.dreamwork.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * Created by seth yang on 2018/2/7
 */
@SuppressWarnings ("unused")
public class HttpClient {
    public static final MediaType JSON = MediaType.parse ("application/json;charset=utf-8");
    public static final MediaType TEXT = MediaType.parse ("text/plain;charset=utf-8");
    public static final MediaType FORM = MediaType.parse ("application/x-www-form-urlencoded");

    private static SSLSocketFactory factory;
    private static final X509TrustManager manager = new TrustedX509Manager ();
    private static final X509TrustManager[] managers = { manager };
    private static final Logger logger = LoggerFactory.getLogger (HttpClient.class);

    private static final ConnectionPool cp = new ConnectionPool (3, 60, TimeUnit.SECONDS);

    /**
     * 使用 {@code HTTP GET} 方法请求资源 url
     * @param url  请求的资源的 url
     * @param type 请求的 content-type
     * @return 请求的资源的结果
     * @throws IOException 任何io异常
     */
    public static HttpResult get (String url, MediaType type) throws IOException {
        return execute (url, null, type, null, HttpMethod.GET);
    }

    /**
     * 使用 {@code HTTP GET} 方法请求 {@code url} 指示的资源.
     *
     * @param url        资源的 url
     * @param header     http 头
     * @param parameters GET 请求的参数
     * @param type       content-type
     * @return 请求的资源的结果
     * @throws IOException 任何 io 异常
     */
    public static HttpResult get (String url, Map<String, String> header,
                                  Map<String, ?> parameters, MediaType type) throws IOException {
        try {
            SSLSocketFactory factory = getSSLSocketFactory ();
            return get (factory, url, header, parameters, type);
        } catch (NoSuchAlgorithmException | KeyManagementException ex) {
            throw new RuntimeException (ex);
        }
    }

    /**
     * 使用 {@code HTTP GET} 方法请求 {@code url} 指示的资源.
     * @param factory    SSL 证书
     * @param url        资源的 url
     * @param header     http 头
     * @param parameters GET 请求的参数
     * @param type       content-type
     * @return 请求的资源的结果
     * @throws IOException 任何 io 异常
     */
    public static HttpResult get (SSLSocketFactory factory, String url, Map<String, String> header,
                                  Map<String, ?> parameters, MediaType type) throws IOException {
        if (parameters != null && !parameters.isEmpty ()) {
            String query = toFormUrlEncoded (parameters);
            url += (url.contains ("?") ? '&' : '?') + query;
        }
        return execute (factory, url, header, type, null, HttpMethod.GET);
    }

    /**
     * 使用 {@code HTTP POST} 方法请求 {@code url} 指示的资源
     * @param url  请求的资源的 url
     * @param body HTTP Body
     * @param type Content-Type
     * @return 结果
     * @throws IOException 任何 io 异常
     */
    public static HttpResult post (String url, String body, MediaType type) throws IOException {
        return execute (url, null, type, body, HttpMethod.POST);
    }

    /**
     * 使用 {@code HTTP POS} 请求 {@code url} 指示的资源
     * @param url    请求的资源的 url
     * @param header HTTP 头
     * @param body   HTTP Body
     * @param type   Content-Type
     * @return 结果
     * @throws IOException 任何 io 异常
     */
    public static HttpResult post (String url, Map<String, String> header, String body, MediaType type) throws IOException {
        return execute (url, header, type, body, HttpMethod.POST);
    }

    public static HttpResult post (String url, Map<String, String> header, Object data, MediaType type) throws IOException {
        try {
            SSLSocketFactory factory = getSSLSocketFactory ();
            return post (factory, url, header, data, type);
        } catch (NoSuchAlgorithmException | KeyManagementException ex) {
            throw new RuntimeException (ex);
        }
    }

    /**
     * 使用 {@code HTTP POS} 请求 {@code url} 指示的资源
     * @param factory SSL 证书
     * @param url     请求的资源的 url
     * @param header  HTTP 头
     * @param data    HTTP Body
     * @param type    Content-Type
     * @return 结果
     * @throws IOException 任何 io 异常
     */
    public static HttpResult post (SSLSocketFactory factory, String url, Map<String, String> header,
                                   Object data, MediaType type) throws IOException {
        if (type == null) {
            type = FORM;
        }
        String content = buildData (data, type);
        return execute (factory, url, header, type, content, HttpMethod.POST);
    }

    /**
     * 使用 {@code HTTP PUT} 请求 {@code url} 指示的资源
     * @param url    请求的资源的 url
     * @param header HTTP 头
     * @param body   HTTP Body
     * @param type   Content-Type
     * @return 结果
     * @throws IOException 任何io异常
     */
    public static HttpResult put (String url, Map<String, String> header, String body, MediaType type) throws IOException {
        return execute (url, header, type, body, HttpMethod.PUT);
    }

    /**
     * 使用 {@code HTTP PUT} 请求 {@code url} 指示的资源
     * @param url    请求的资源的 url
     * @param body   HTTP Body
     * @param type   Content-Type
     * @return 结果
     * @throws IOException 任何io异常
     */
    public static HttpResult put (String url, String body, MediaType type) throws IOException {
        return execute (url, null, type, body, HttpMethod.PUT);
    }

    /**
     * 使用 {@code HTTP PUT} 请求 {@code url} 指示的资源
     * @param url     请求的资源的 url
     * @param header  HTTP 头
     * @param data    HTTP Body
     * @param type    Content-Type
     * @return 结果
     * @throws IOException 任何 io 异常
     */
    public static HttpResult put (String url, Map<String, String> header, Object data, MediaType type) throws IOException {
        try {
            SSLSocketFactory factory = getSSLSocketFactory ();
            return put (factory, url, header, data, type);
        } catch (NoSuchAlgorithmException | KeyManagementException ex) {
            throw new RuntimeException (ex);
        }
    }

    /**
     * 使用 {@code HTTP PUT} 请求 {@code url} 指示的资源
     * @param factory SSL 证书
     * @param url     请求的资源的 url
     * @param header  HTTP 头
     * @param data    HTTP Body
     * @param type    Content-Type
     * @return 结果
     * @throws IOException 任何 io 异常
     */
    public static HttpResult put (SSLSocketFactory factory, String url, Map<String, String> header,
                                  Object data, MediaType type) throws IOException {
        String content = buildData (data, type);
        return execute (factory, url, header, type, content, HttpMethod.PUT);
    }

    @Deprecated
    public static HttpResult delete (String url, Map<String, String> header, String body, MediaType type) throws IOException {
        return execute (url, header, type, body, HttpMethod.DELETE);
    }

    /**
     * 请求删除 {@code url} 指示的资源
     * @param url        资源 url
     * @param header     http 头
     * @param parameters 参数
     * @param type       content-type
     * @return 删除请求的结果
     * @throws IOException 任何 io 异常
     */
    public static HttpResult delete (String url, Map<String, String> header, Map<String, ?> parameters, MediaType type) throws IOException {
        try {
            return delete (getSSLSocketFactory (), url, header, parameters, type);
        } catch (NoSuchAlgorithmException | KeyManagementException ex) {
            throw new RuntimeException (ex);
        }
    }

    /**
     * 请求删除 {@code url} 指示的资源
     * @param factory    ssl 证书
     * @param url        资源的 url
     * @param header     http 头
     * @param parameters 参数
     * @param type       content-type
     * @return 删除请求的结果
     * @throws IOException 任何 io 异常
     */
    public static HttpResult delete (SSLSocketFactory factory, String url, Map<String, String> header,
                                     Map<String, ?> parameters, MediaType type) throws IOException {
        String query = toFormUrlEncoded (parameters);
        if (!StringUtil.isEmpty (query)) {
            url += ((url.contains ("?")) ? '&' : '?') + query;
        }
        return execute (factory, url, header, type, null, HttpMethod.DELETE);
    }

    /**
     * 下载 {@code url} 指示的资源到 {@code out} 流中
     * @param url 资源的 url
     * @return 删除请求的结果
     * @throws IOException 任何 io 异常
     */
    public static int download (String url, OutputStream out) throws IOException {
        return download (url, null, null, out);
    }

    /**
     * 下载 {@code url} 指示的资源到 {@code out} 流中
     * @param url        资源的 url
     * @param header     http 头
     * @param parameters 参数
     * @return 删除请求的结果
     * @throws IOException 任何 io 异常
     */
    public static int download (String url, Map<String, String> header, Map<String, ?> parameters, OutputStream out) throws IOException {
        return download (null, url, header, parameters, out);
    }

    /**
     * 下载 {@code url} 指示的资源到 {@code out} 流中
     * @param factory    ssl 证书
     * @param url        资源的 url
     * @return 删除请求的结果
     * @throws IOException 任何 io 异常
     */
    public static int download (SSLSocketFactory factory, String url, OutputStream out) throws IOException {
        return download (factory, url, null, null, out);
    }

    /**
     * 下载 {@code url} 指示的资源到 {@code out} 流中
     * @param factory    ssl 证书
     * @param url        资源的 url
     * @param header     http 头
     * @param parameters 参数
     * @return 删除请求的结果
     * @throws IOException 任何 io 异常
     */
    public static int download (SSLSocketFactory factory, String url, Map<String, String> header,
                                Map<String, ?> parameters, OutputStream out) throws IOException {
        try {
            String query = toFormUrlEncoded (parameters);
            if (!StringUtil.isEmpty (query)) {
                url += (url.contains ("?") ? '&' : '?') + query;
            }
            if (factory == null) {
                factory = getSSLSocketFactory ();
            }
            OkHttpClient client = createBuilder (factory, url).build ();
            Request.Builder builder = new Request.Builder ().url (url).get ();
            if (header != null && !header.isEmpty ()) {
                header.forEach (builder::header);
            }
            try (Response response = client.newCall (builder.build ()).execute ()) {
                if (response.isSuccessful ()) {
                    ResponseBody body = response.body ();
                    if (body != null) {
                        InputStream in = body.byteStream ();
                        IOUtil.dump (in, out);
                    }
                }
                return response.code ();
            }
        } catch (NoSuchAlgorithmException | KeyManagementException ex) {
            logger.warn (ex.getMessage (), ex);
            throw new RuntimeException (ex);
        }
    }

    static HttpResult execute (String url, Map<String, String> header, MediaType type, String content, HttpMethod method) throws IOException {
        try {
            return execute (getSSLSocketFactory (), url, header, type, content, method);
        } catch (NoSuchAlgorithmException | KeyManagementException ex) {
            logger.warn (ex.getMessage (), ex);
            throw new RuntimeException (ex);
        }
    }

    public static Response call (SSLSocketFactory factory,
                                 String url,
                                 Map<String, String> header,
                                 MediaType type,
                                 String content,
                                 HttpMethod method) throws IOException {
        OkHttpClient client = createBuilder (factory, url).build ();
        RequestBody body;
        if (StringUtil.isEmpty (content)) {
            body = RequestBody.create ("", type);
        } else {
            body = RequestBody.create (content, type);
        }

        Request.Builder builder = new Request.Builder ();
        if (header != null && !header.isEmpty ()) {
            for (String key : header.keySet ()) {
                builder.header (key, header.get (key));
            }
        }
        switch (method) {
            case GET:
                builder.get ();
                break;
            case POST:
                builder.post (body);
                break;
            case PUT:
                builder.put (body);
                break;
            case DELETE:
                builder.delete ();
                break;
        }
        builder.url (url);
        return client.newCall (builder.build ()).execute ();
    }

    static HttpResult execute (SSLSocketFactory factory,
                               String url,
                               Map<String, String> header,
                               MediaType type,
                               String content,
                               HttpMethod method) throws IOException {

        Response response = call (factory, url, header, type, content, method);
        return translate (response);
    }

    static HttpResult translate (Response response) throws IOException {
        try {
            int code = response.code ();
            HttpResult hr = new HttpResult ();
            hr.contentType = response.header ("Content-Type");
            Set<String> names = response.headers ().names ();
            names.forEach (name -> {
                List<String> values = response.headers (name);
                if (values.size () == 1) {
                    hr.header.set (name, values.get (0));
                } else if (values.size () > 1) {
                    hr.header.set (name, values);
                }
            });
            hr.code        = code;
            ResponseBody body = response.body ();
            if (body != null)
                hr.content     = body.string ();
            hr.success     = response.isSuccessful ();
            hr.timestamp   = response.receivedResponseAtMillis ();
            return hr;
        } finally {
            if (response != null) {
                ResponseBody body = response.body ();
                if (body != null)
                    body.close ();
                response.close ();
            }
        }
    }

    private static OkHttpClient.Builder createBuilder (String url) throws IOException, NoSuchAlgorithmException, KeyManagementException {
        return createBuilder (getSSLSocketFactory (), url);
    }

    private static OkHttpClient.Builder createBuilder (SSLSocketFactory factory, String url) throws MalformedURLException {
        OkHttpClient.Builder builder = new OkHttpClient.Builder ().connectionPool (cp);
        builder.writeTimeout (30, TimeUnit.SECONDS)
                .connectTimeout (30, TimeUnit.SECONDS)
                .readTimeout (30, TimeUnit.SECONDS);
        URL u = new URL (url);
        if ("https".equalsIgnoreCase (u.getProtocol ())) {
            builder.sslSocketFactory (factory, manager)
                    .hostnameVerifier ((s, session) -> true);
        } else if (logger.isTraceEnabled ()) {
            logger.warn ("url: {} does not need ssl socket factory!", url);
        }
        return builder;
    }

    public synchronized static SSLSocketFactory getSSLSocketFactory () throws NoSuchAlgorithmException, KeyManagementException {
        if (factory == null) {
            SSLContext context = SSLContext.getInstance ("SSL");
            context.init (null, new TrustManager[] {manager}, null);
            factory = context.getSocketFactory ();
        }
        return factory;
    }

    public static SSLSocketFactory getSSLSocketFactory (String fileName, char[] password)
            throws NoSuchAlgorithmException, KeyManagementException, IOException, UnrecoverableKeyException,
                   CertificateException, KeyStoreException {
        if (StringUtil.isEmpty (fileName)) {
            logger.warn ("empty file, using default ssl socket factory");
            return getSSLSocketFactory ();
        }

        Path path = Paths.get (fileName);
        if (!Files.exists (path)) {
            logger.warn ("file: {} not exists. using default ssl socket factory", fileName);
            return getSSLSocketFactory ();
        }

        try (InputStream in = Files.newInputStream (path)) {
            return getSSLSocketFactory (in, password);
        }
    }

    public static SSLSocketFactory getSSLSocketFactory (InputStream in, char[] password)
            throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, CertificateException,
                   IOException, UnrecoverableKeyException {
        return getSSLSocketFactory (in, password, null, null);
    }

    public static SSLSocketFactory getSSLSocketFactory (String serverCertFile, char[] serverCertPassword,
                                                        String clientCertFile, char[] clientCertPassword)
            throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, CertificateException,
                   IOException, UnrecoverableKeyException {
        InputStream server = null, client = null;
        if (StringUtil.isEmpty (serverCertFile)) {
            logger.warn ("empty server cert file. using default server socket factory. ");
        } else {
            Path path = Paths.get (serverCertFile);
            if (!Files.exists (path)) {
                logger.warn ("server cert file: {} not exists. using default server socket factory.", serverCertFile);
            } else {
                server = Files.newInputStream (path);
            }
        }

        if (StringUtil.isEmpty (clientCertFile)) {
            logger.warn ("empty client cert file. using empty client socket factory.");
        } else {
            Path path = Paths.get (clientCertFile);
            if (!Files.exists (path)) {
                logger.warn ("client cert file: {} not exists. using empty client socket factory", clientCertFile);
            } else {
                client = Files.newInputStream (path);
            }
        }

        if (server == null && client == null) {
            return getSSLSocketFactory ();
        } else {
            try {
                return getSSLSocketFactory (server, serverCertPassword, client, clientCertPassword);
            } finally {
                if (server != null) try {
                    server.close ();
                } catch (IOException ignore) {}

                if (client != null) try {
                    client.close ();
                } catch (IOException ignore) {}
            }
        }
    }

    public static SSLSocketFactory getSSLSocketFactory (InputStream server, char[] serverPassword,
                                                        InputStream client, char[] clientPassword)
            throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, CertificateException,
            IOException, UnrecoverableKeyException {
        KeyManager[] keyManagers = null;
        if (server != null) {
            KeyStore cert = KeyStore.getInstance ("pkcs12");
            cert.load (server, serverPassword);
            KeyManagerFactory kmf = KeyManagerFactory.getInstance ("sunx509");
            kmf.init (cert, serverPassword);
            keyManagers = kmf.getKeyManagers();
        }

        TrustManager[] trustManagers = null;
        if (client != null) {
            KeyStore caCert = KeyStore.getInstance("jks");
            caCert.load(client, clientPassword);
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("sunx509");
            tmf.init(caCert);
            trustManagers = tmf.getTrustManagers ();
        }
        if (trustManagers == null) {
            trustManagers = managers;
        }

        SSLContext context = SSLContext.getInstance("SSL");
        context.init(keyManagers, trustManagers, null);
        return  context.getSocketFactory ();
    }

    public static String toFormUrlEncoded (Map<String, ?> data) {
        if (data == null || data.isEmpty ()) {
            return "";
        }

        StringBuilder builder = new StringBuilder ();
        data.forEach ((key, value) -> {
            if (builder.length () > 0) {
                builder.append ('&');
            }
            builder.append (key).append ('=');
            if (value != null) {
                String text = null;
                try {
                    text = URLEncoder.encode (String.valueOf (value), "UTF-8");
                } catch (UnsupportedEncodingException ignore) {
                }
                builder.append (text);
            }
        });
        return builder.toString ();
    }

    public static String buildData (Object data, MediaType type) {
        String content;
        if (data == null) {
            return "";
        }

        if (data instanceof Map) {
            @SuppressWarnings ("unchecked")
            Map<String, ?> map = (Map<String, ?>) data;
            if (!map.isEmpty ()) {
                if (type != null && "json".equalsIgnoreCase (type.subtype ())) {
                    content = GsonHelper.getGson ().toJson (map);
                } else {
                    content = toFormUrlEncoded (map);
                }
            } else {
                content = "";
            }
        } else if (data instanceof CharSequence) {
            return data.toString ();
        } else {
            content = GsonHelper.getGson ().toJson (data);
        }

        return content;
    }
}
