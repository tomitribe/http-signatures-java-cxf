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

import org.apache.cxf.Bus;
import org.apache.cxf.feature.AbstractFeature;
import org.apache.cxf.feature.Feature;
import org.apache.cxf.interceptor.InterceptorProvider;

import java.util.Collection;
import java.util.LinkedList;

/**
 * All in one feature for date, signature and digest ones.
 */
public class SecurityFeature extends AbstractFeature {
    private final Collection<Feature> delegates = new LinkedList<>();

    public SecurityFeature(final String digest, final String key, final String alias, final String algorithm, final String headers) {
        delegates.add(new DateFeature());
        delegates.add(new DigestFeature(digest));
        delegates.add(new SignatureFeature(key, alias, algorithm, headers));
    }

    @Override
    protected void initializeProvider(final InterceptorProvider provider, final Bus bus) {
        for (final Feature f : delegates) {
            f.initialize(provider, bus);
        }
    }
}
