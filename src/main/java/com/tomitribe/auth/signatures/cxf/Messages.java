/*
 * Tomitribe Confidential
 *
 * Copyright Tomitribe Corporation. 2015
 *
 * The source code for this program is not published or otherwise divested 
 * of its trade secrets, irrespective of what has been deposited with the 
 * U.S. Copyright Office.
 */
package com.tomitribe.auth.signatures.cxf;

import org.apache.cxf.message.Message;

import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public enum Messages {
    ;

    public static Map<String, List<String>> getHeaders(Message message) {

        final Map<String, List<String>> a = (Map<String, List<String>>) message.get(Message.PROTOCOL_HEADERS);
        if (a != null) return a;

        final Map<String, List<String>> b = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        message.put(Message.PROTOCOL_HEADERS, b);
        return b;
    }
}
