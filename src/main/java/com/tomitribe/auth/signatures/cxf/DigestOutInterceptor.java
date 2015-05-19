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
import org.apache.cxf.interceptor.StaxOutInterceptor;
import org.apache.cxf.message.Message;
import org.apache.cxf.phase.AbstractPhaseInterceptor;
import org.apache.cxf.phase.Phase;
import org.tomitribe.auth.signatures.Base64;

import java.io.IOException;
import java.io.OutputStream;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
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

    public DigestOutInterceptor(final String phase, final String digest) {
        super(phase);
        this.digest = digest;
        addBefore(StaxOutInterceptor.class.getName());
    }

    public DigestOutInterceptor(final String digest) {
        this(Phase.PRE_STREAM, digest);
    }

    @Override
    public void handleMessage(final Message message) throws Fault {

        // wrap the output stream to calculate the digest on the fly
        final OutputStream out = message.getContent(OutputStream.class);
        try {
            final DigestOutputStream dos = new DigestOutputStream(out, MessageDigest.getInstance(digest)) {

                @Override
                public void write(int b) throws IOException {
                    super.write(b);
                }

                @Override
                public void write(byte[] b, int off, int len) throws IOException {
                    super.write(b, off, len);
                }

                @Override
                public void write(byte[] b) throws IOException {
                    super.write(b);
                }

                @Override
                public void close() throws IOException {

                    byte digest[] = getMessageDigest().digest();

                    Map<String, List<String>> headers = (Map<String, List<String>>) message.get(Message.PROTOCOL_HEADERS);
                    if (headers == null) {
                        headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
                        message.put(Message.PROTOCOL_HEADERS, headers);
                    }

                    final String digestHeaderKey = "Digest";
                    final String base64EncodedDigest = getMessageDigest().getAlgorithm() + "=" + new String(Base64.encodeBase64(digest));

                    headers.put(digestHeaderKey, Arrays.asList(base64EncodedDigest));

                    super.close();
                }

            };

            message.setContent(OutputStream.class, dos);

            // add the DigestOutputStream into the Message map so that
            // another interceptor can use it.
            message.put("digest.stream", dos);

        } catch (final NoSuchAlgorithmException e) {
            LOGGER.log(Level.SEVERE, "Can not initialise MessageDigest for " + digest, e);
        }
    }
}
