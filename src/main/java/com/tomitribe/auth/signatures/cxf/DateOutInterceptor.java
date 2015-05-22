/*
 * Tomitribe Confidential
 *
 * Copyright(c) Tomitribe Corporation. 2015
 *
 * The source code for this program is not published or otherwise divested
 * of its trade secrets, irrespective of what has been deposited with the
 * U.S. Copyright Office.
 */

package com.tomitribe.auth.signatures.cxf;

import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.message.Message;
import org.apache.cxf.phase.AbstractPhaseInterceptor;
import org.apache.cxf.phase.Phase;

import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

/**
 * Technical CXF interceptor to fill it automatically the date in the header.
 */
public class DateOutInterceptor extends AbstractPhaseInterceptor<Message> {

    public DateOutInterceptor(final String phase) {
        super(phase);
        addBefore(DigestOutInterceptor.class.getName());
    }

    public DateOutInterceptor() {
        this(Phase.PRE_STREAM);
    }


    @Override
    public void handleMessage(Message message) throws Fault {

        Map<String, List<String>> headers = (Map<String, List<String>>) message.get(Message.PROTOCOL_HEADERS);
        if (headers == null) {
            headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            message.put(Message.PROTOCOL_HEADERS, headers);
        }

        final String dateFormatPattern = "EEE, dd MMM yyyy HH:mm:ss zzz";
        final String dateHeaderKey = "Date";

        final String date = new SimpleDateFormat(dateFormatPattern, Locale.US).format(new Date());
        headers.put(dateHeaderKey, Arrays.asList(date));
    }
}
