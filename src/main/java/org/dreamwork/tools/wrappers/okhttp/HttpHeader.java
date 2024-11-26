package org.dreamwork.tools.wrappers.okhttp;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

@SuppressWarnings ({"unchecked", "unused"})
public class HttpHeader extends HashMap<String, Object> {
    public void set (String name, String value) {
        super.put (name, value);
    }

    public void set (String name, List<String> values) {
        super.put (name, values);
    }

    public void add (String name, String value) {
        List<String> list = (List<String>) super.computeIfAbsent (name, key -> new ArrayList<> ());
        list.add (value);
    }

    public String string (String name) {
        return (String) super.get (name);
    }

    public Date date (String name) {
        String temp = string (name);
        if (temp != null) {
            try {
                return new SimpleDateFormat ("yyyy-MM-dd").parse (temp);
            } catch (Exception ex) {
                throw new RuntimeException (ex);
            }
        }
        return null;
    }

    public Integer integer (String name) {
        String temp = string (name);
        if (temp != null) {
            try {
                return Integer.valueOf (temp);
            } catch (Exception ex) {
                throw new RuntimeException (ex);
            }
        }
        return null;
    }

    public List<String> list (String name) {
        return (List<String>) super.get (name);
    }
}