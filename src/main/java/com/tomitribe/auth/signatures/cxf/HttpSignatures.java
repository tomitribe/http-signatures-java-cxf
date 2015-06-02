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

import com.tomitribe.auth.signatures.cxf.interceptor.DateOutInterceptor;
import com.tomitribe.auth.signatures.cxf.interceptor.SignatureOutInterceptor;
import org.apache.cxf.jaxrs.client.WebClient;

import javax.crypto.spec.SecretKeySpec;

/**
 * This is a utility class to get a CXF WebClient and properly configure the
 * out interceptors responsible for including Date, Digest and HTTP Signature headers.
 *
 * @deprecated either use {@see org.apache.cxf.jaxrs.client.JAXRSClientFactoryBean}
 * or directly {@see org.apache.cxf.jaxrs.client.WebClient} with features
 *
 * Example:
 *
 * final JAXRSClientFactoryBean bean = new JAXRSClientFactoryBean();
 * bean.setThreadSafe(true);
 * bean.setAddress(endpoint);
 * bean.setProvider(new JohnzonProvider());
 * bean.getFeatures().add(new SecurityFeature(digest, secret, alias, algorithm, headers));
 * client = bean.createWebClient();
 *
 */
@Deprecated
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
