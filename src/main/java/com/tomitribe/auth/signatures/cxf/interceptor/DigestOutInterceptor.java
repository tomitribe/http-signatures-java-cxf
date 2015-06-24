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

import com.tomitribe.auth.signatures.cxf.internal.TwoPhaseCloseDigestOutputStream;
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.interceptor.StaxOutInterceptor;
import org.apache.cxf.message.Message;
import org.apache.cxf.phase.AbstractPhaseInterceptor;
import org.apache.cxf.phase.Phase;

import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Technical CXF interceptor to stream the output payload and
 * compute the digest header.
 * <p/>
 * The header will be automatically added when the Stream gets closed.
 */
public class DigestOutInterceptor extends AbstractPhaseInterceptor<Message> {
    private static final Logger LOGGER = Logger.getLogger(DigestOutInterceptor.class.getName());

    private final String digest;

    public DigestOutInterceptor(final String digest) {
        super(Phase.PRE_STREAM);
        this.digest = digest;
        addBefore(StaxOutInterceptor.class.getName());
    }

    @Override
    public void handleMessage(final Message message) throws Fault {
        // wrap the output stream to calculate the digest on the fly
        try {
            final OutputStream dos = new TwoPhaseCloseDigestOutputStream(
                    message.getContent(OutputStream.class), MessageDigest.getInstance(digest), message);
            message.setContent(OutputStream.class, dos);

            // add the DigestOutputStream into the Message map so that
            // another interceptor can use it.
            message.put("digest.stream", dos);
        } catch (final NoSuchAlgorithmException e) {
            LOGGER.log(Level.SEVERE, "Can not initialise MessageDigest for " + digest, e);
        }
    }
}
