/*
 * Tomitribe Confidential
 *
 * Copyright(c) Tomitribe Corporation. 2015
 *
 * The source code for this program is not published or otherwise divested
 * of its trade secrets, irrespective of what has been deposited with the
 * U.S. Copyright Office.
 */

package com.tomitribe.auth.signatures.cxf.interceptor;

import com.tomitribe.auth.signatures.cxf.internal.Messages;
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.message.Message;
import org.apache.cxf.phase.AbstractPhaseInterceptor;
import org.apache.cxf.phase.Phase;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;

import static java.util.Collections.singletonList;

/**
 * Technical CXF interceptor to fill it automatically the date in the header.
 */
public class DateOutInterceptor extends AbstractPhaseInterceptor<Message> {
    private static final String DATE_HEADER = "Date";

    // Avoid to leak if in a webapp
    private final Queue<DateFormat> dateFormats = new ConcurrentLinkedQueue<>();

    public DateOutInterceptor() {
        super(Phase.PRE_STREAM);
    }

    @Override
    public void handleMessage(final Message message) throws Fault {
        final DateFormat format = format();
        try {
            final String date = format.format(new Date());
            Messages.getHeaders(message).put(DATE_HEADER, singletonList(date));
        } finally {
            dateFormats.add(format);
        }
    }

    private DateFormat format() {
        final DateFormat format = dateFormats.poll();
        return format != null ? format : new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz", Locale.US);
    }
}
