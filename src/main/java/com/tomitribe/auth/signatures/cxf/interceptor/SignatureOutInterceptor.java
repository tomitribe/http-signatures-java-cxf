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
import com.tomitribe.auth.signatures.cxf.internal.TwoPhaseCloseDigestOutputStream;
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.interceptor.StaxOutInterceptor;
import org.apache.cxf.message.Message;
import org.apache.cxf.phase.AbstractPhaseInterceptor;
import org.apache.cxf.phase.Phase;
import org.apache.cxf.transport.http.Headers;
import org.tomitribe.auth.signatures.Algorithm;
import org.tomitribe.auth.signatures.Signature;
import org.tomitribe.auth.signatures.Signer;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Technical CXF interceptor responsible for calculating the HTTP Signature and
 * adding it automatically to the headers.
 */
public class SignatureOutInterceptor extends AbstractPhaseInterceptor<Message> {
    private final Signer signer;

    public SignatureOutInterceptor(final Key key, final String keyAlias, final String algorithm, final String headers) {
        super(Phase.MARSHAL);
        addBefore(StaxOutInterceptor.class.getName());
        addAfter(DateOutInterceptor.class.getName());
        addAfter(DigestOutInterceptor.class.getName());


        final String[] headerList = headers.split(" ");
        final Signature signature = new Signature(keyAlias, Algorithm.get(algorithm), null, headerList);
        signer = new Signer(key, signature);
    }


    @Override
    public void handleMessage(final Message message) throws Fault {
        final OutputStream out = message.getContent(OutputStream.class);
        final OutputStream dos = new FilterOutputStream(out) {
            @Override
            public void write(final byte[] b, final int off, final int len) throws IOException {
                out.write(b, off, len);
            }

            @Override
            public void write(final byte[] b) throws IOException {
                out.write(b);
            }

            @Override
            public void close() throws IOException {
                final Map<String, List<String>> headers = Messages.getHeaders(message);

                // if Digest is used, force the stream to close so that the digest header gets added and no one
                // else can change it
                final TwoPhaseCloseDigestOutputStream dos = TwoPhaseCloseDigestOutputStream.class.cast(message.get("digest.stream"));
                if (dos != null) {
                    dos.addDigestHeader();
                }

                headers.put("Authorization", Arrays.asList(getAuthorization(message)));
                super.close();
            }

        };

        message.setContent(OutputStream.class, dos);

    }

    private String getAuthorization(final Message message) {

        final Map<String, List<String>> headers = Headers.getSetProtocolHeaders(message);
        final List<String> existing = headers.get("authorization");

        // if there is already an header let it be
        if (existing != null && !existing.isEmpty()) {
            return existing.iterator().next();
        }

        final URL url;
        try {
            url = new URL(message.get(Message.REQUEST_URI).toString());
        } catch (MalformedURLException e) {
            throw new IllegalStateException(e);
        }

        try {
            final String uri = url.getFile();
            return sign(
                    message.get(Message.HTTP_REQUEST_METHOD).toString(),
                    uri,
                    Headers.getSetProtocolHeaders(message));

        } catch (final NoSuchAlgorithmException | InvalidKeyException | IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private String sign(final String method, final String uri, final Map<String, List<String>> headers) throws NoSuchAlgorithmException, InvalidKeyException, IOException {

        final Map<String, String> h = new HashMap<>(headers != null ? headers.size() : 0);
        if (headers != null) {
            for (final Map.Entry<String, List<String>> e : headers.entrySet()) {
                final List<String> value = e.getValue();
                if (value != null && !value.isEmpty()) {
                    h.put(e.getKey(), value.iterator().next());
                }
            }
        }

        return signer.sign(method, uri, h).toString();
    }

}
