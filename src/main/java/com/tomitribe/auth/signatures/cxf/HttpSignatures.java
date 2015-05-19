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

import org.apache.cxf.jaxrs.client.WebClient;

import javax.crypto.spec.SecretKeySpec;

/**
 * This is a utility class to get a CXF WebClient and properly configure the
 * out interceptors responsible for including Date, Digest and HTTP Signature headers.
 */
public class HttpSignatures {

    private HttpSignatures() {
        // utility class so no public constructor
    }

    public static WebClient httpSignatureClient(
            final String baseUrl,
            final String digestAlgorithm,
            final String signatureKeyValue,
            final String signatureAlgorithm,
            final String signatureKeyId,
            final String signatureHeaders) {

        // build the CXF Web CLient
        final WebClient webClient = WebClient.create(baseUrl);

        // add all the output interceptors
//        WebClient.getConfig(webClient).getOutInterceptors().add(new DigestOutInterceptor(digestAlgorithm));
        WebClient.getConfig(webClient).getOutInterceptors().add(new DateOutInterceptor());
        WebClient.getConfig(webClient).getOutInterceptors().add(new SignatureOutInterceptor(
                new SecretKeySpec(signatureKeyValue.getBytes(), signatureAlgorithm),
                signatureKeyId,
                signatureAlgorithm, signatureHeaders
        ));

        return webClient;
    }

}
