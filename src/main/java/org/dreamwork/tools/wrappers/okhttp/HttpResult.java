package org.dreamwork.tools.wrappers.okhttp;

/**
 * Created by seth yang on 2017/2/16
 */
public class HttpResult {
    public int code;
    public boolean success;
    public String content, contentType;
    public long timestamp;
    public HttpHeader header = new HttpHeader ();
}