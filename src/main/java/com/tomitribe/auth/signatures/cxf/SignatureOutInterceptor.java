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
import org.apache.cxf.transport.http.Headers;
import org.tomitribe.auth.signatures.Algorithm;
import org.tomitribe.auth.signatures.Signature;
import org.tomitribe.auth.signatures.Signer;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.DigestOutputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Technical CXF interceptor responsible for calculating the HTTP Signature and
 * adding it automatically to the headers.
 */
public class SignatureOutInterceptor extends AbstractPhaseInterceptor<Message> {

    private final Key key;
    private final String keyAlias;
    private final Algorithm algorithm;
    private final String consideredHeaders;

    public SignatureOutInterceptor(final String phase,
                                   final Key key, final String keyAlias, final String algorithm, final String headers) {

        super(phase);
        addBefore(StaxOutInterceptor.class.getName());
        addAfter(DigestOutInterceptor.class.getName());

        this.key = key;
        this.keyAlias = keyAlias;
        this.algorithm = Algorithm.get(algorithm);
        this.consideredHeaders = headers;
    }

    public SignatureOutInterceptor(final Key key, final String keyAlias, final String algorithm, final String headers) {
        this(Phase.MARSHAL, key, keyAlias, algorithm, headers);
    }


    @Override
    public void handleMessage(final Message message) throws Fault {

        Map<String, List<String>> headers = (Map<String, List<String>>) message.get(Message.PROTOCOL_HEADERS);
        if (headers == null) {
            headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            message.put(Message.PROTOCOL_HEADERS, headers);
        }

        // if Digest is used, force the stream to close so that the digest header gets added and no one
        // else can change it
        final DigestOutputStream dos = (DigestOutputStream) message.get("digest.stream");
        if (dos != null) {
            try {
                dos.close();
            } catch (final IOException e) {
                throw new IllegalStateException(e);
            }
        }

        headers.put("Authorization", Arrays.asList(getAuthorization(message)));
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
            url = new URL(message.get("org.apache.cxf.request.uri").toString());

        } catch (MalformedURLException e) {
            throw new IllegalStateException(e);
        }

        try {
            return sign(
                    message.get("org.apache.cxf.request.method").toString(),
                    url.getPath(),
                    Headers.getSetProtocolHeaders(message));

        } catch (final NoSuchAlgorithmException | InvalidKeyException | IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private String sign(final String method, final String uri, final Map<String, List<String>> headers) throws NoSuchAlgorithmException, InvalidKeyException, IOException {

        final String[] headerList = consideredHeaders.split(" ");
        final Signature signature = new Signature(keyAlias, algorithm, null, headerList);
        final Signer signer = new Signer(key, signature);

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
