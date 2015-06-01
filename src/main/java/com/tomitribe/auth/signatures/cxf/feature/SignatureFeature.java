/*
 * Tomitribe Confidential
 *
 * Copyright(c) Tomitribe Corporation. 2015
 *
 * The source code for this program is not published or otherwise divested
 * of its trade secrets, irrespective of what has been deposited with the
 * U.S. Copyright Office.
 */
package com.tomitribe.auth.signatures.cxf.feature;

import com.tomitribe.auth.signatures.cxf.SignatureOutInterceptor;
import org.apache.cxf.Bus;
import org.apache.cxf.feature.AbstractFeature;
import org.apache.cxf.interceptor.InterceptorProvider;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

/**
 * Activates {@see SignatureOutInterceptor}
 */
public class SignatureFeature extends AbstractFeature {
    private final Key key;
    private final String alias;
    private final String algorithm;
    private final String headers;

    public SignatureFeature(final String key, final String alias, final String algorithm, final String headers) {
        this.key = new SecretKeySpec(key.getBytes(), algorithm);
        this.alias = alias;
        this.algorithm = algorithm;
        this.headers = headers;
    }

    @Override
    protected void initializeProvider(final InterceptorProvider provider, final Bus bus) {
        provider.getOutInterceptors().add(new SignatureOutInterceptor(key, alias, algorithm, headers));
    }
}
