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

import com.tomitribe.auth.signatures.cxf.interceptor.DigestOutInterceptor;
import org.apache.cxf.Bus;
import org.apache.cxf.feature.AbstractFeature;
import org.apache.cxf.interceptor.InterceptorProvider;

/**
 * Activates {@see DigestOutInterceptor}
 */
public class DigestFeature extends AbstractFeature {
    private final String digest;

    public DigestFeature(final String digest) {
        this.digest = digest;
    }

    @Override
    protected void initializeProvider(final InterceptorProvider provider, final Bus bus) {
        provider.getOutInterceptors().add(new DigestOutInterceptor(digest));
    }
}
