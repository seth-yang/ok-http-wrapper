package org.dreamwork.tools.wrappers.okhttp;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import java.net.Socket;
import java.security.cert.X509Certificate;

/**
 * Created by seth yang on 2017/11/2
 */
public class TrustedX509Manager extends X509ExtendedTrustManager {
    @Override
    public void checkClientTrusted (X509Certificate[] x509Certificates, String s, Socket socket) {
    }

    @Override
    public void checkServerTrusted (X509Certificate[] x509Certificates, String s, Socket socket) {
    }

    @Override
    public void checkClientTrusted (X509Certificate[] x509Certificates, String s, SSLEngine sslEngine) {
    }

    @Override
    public void checkServerTrusted (X509Certificate[] x509Certificates, String s, SSLEngine sslEngine) {
    }

    @Override
    public void checkClientTrusted (X509Certificate[] x509Certificates, String s) {
    }

    @Override
    public void checkServerTrusted (X509Certificate[] x509Certificates, String s) {
    }

    @Override
    public X509Certificate[] getAcceptedIssuers () {
        return new X509Certificate[0];
    }
}
