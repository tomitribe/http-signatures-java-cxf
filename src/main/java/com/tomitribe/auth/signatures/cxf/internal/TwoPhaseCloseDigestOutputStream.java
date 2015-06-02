/*
 * Tomitribe Confidential
 *
 * Copyright(c) Tomitribe Corporation. 2015
 *
 * The source code for this program is not published or otherwise divested
 * of its trade secrets, irrespective of what has been deposited with the
 * U.S. Copyright Office.
 */
package com.tomitribe.auth.signatures.cxf.internal;

import org.apache.cxf.message.Message;
import org.tomitribe.auth.signatures.Base64;

import java.io.IOException;
import java.io.OutputStream;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.util.List;
import java.util.Map;

import static java.util.Collections.singletonList;

public class TwoPhaseCloseDigestOutputStream extends DigestOutputStream {
    private final Message message;
    private boolean digested;

    public TwoPhaseCloseDigestOutputStream(final OutputStream out, final MessageDigest instance, final Message message) {
        super(out, instance);
        this.message = message;
    }

    @Override
    public void write(final int b) throws IOException {
        super.write(b);
    }

    @Override
    public void write(final byte[] b, final int off, final int len) throws IOException {
        super.write(b, off, len);
    }

    @Override
    public void write(final byte[] b) throws IOException {
        super.write(b);
    }

    @Override
    public void close() throws IOException {
        if (!digested) {
            addDigestHeader();
        }
        super.close();
    }

    public void addDigestHeader() {
        final byte digest[] = getMessageDigest().digest();
        final Map<String, List<String>> headers = Messages.getHeaders(message);
        final String base64EncodedDigest = getMessageDigest().getAlgorithm() + "=" + new String(Base64.encodeBase64(digest));
        headers.put("Digest", singletonList(base64EncodedDigest));
        digested = true;
    }
}
