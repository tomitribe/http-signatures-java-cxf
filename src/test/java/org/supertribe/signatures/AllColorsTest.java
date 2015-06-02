/*
 * Tomitribe Confidential
 *
 * Copyright(c) Tomitribe Corporation. 2015
 *
 * The source code for this program is not published or otherwise divested
 * of its trade secrets, irrespective of what has been deposited with the
 * U.S. Copyright Office.
 */
package org.supertribe.signatures;

import com.tomitribe.auth.signatures.cxf.feature.SecurityFeature;
import com.tomitribe.tribestream.security.signatures.store.StoreManager;
import org.apache.cxf.feature.AbstractFeature;
import org.apache.cxf.jaxrs.client.WebClient;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.ClassLoaderAsset;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.tomitribe.util.Files;

import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileFilter;
import java.net.URL;
import java.util.Collections;

import static org.junit.Assert.assertEquals;
import static org.tomitribe.util.JarLocation.jarLocation;

@RunWith(Arquillian.class)
public class AllColorsTest {
    private static final String DIGEST_ALGORITHM = "sha1";
    private static final String SIGNATURE_HEADERS = "(request-target) date digest";

    @Deployment(testable = false)
    public static WebArchive war() throws Exception {
        // create the test certificate used by the app
        final File certFile = new File(
                new File(jarLocation(AllColorsTest.class).getParentFile(), "tribestream-remote")
                        .listFiles(new FileFilter() {
                            @Override
                            public boolean accept(final File f) {
                                return f.isDirectory() && f.getName().startsWith("tribestream-");
                            }
                        })[0],
                "conf/AllColorsTest.jks");
        Files.mkdirs(certFile.getParentFile());

        final StoreManager mgr = StoreManager.get(certFile.getAbsolutePath(), "changeit".toCharArray(), true);
        mgr.addSecretKey(KeystoreInitializer.KEY_ALIAS, "changeit".toCharArray(), new SecretKeySpec(KeystoreInitializer.SECRET.getBytes(), "HmacSHA256"));

        return ShrinkWrap.create(WebArchive.class, "colors-all.war")
                .addPackages(true, "org.supertribe.signatures")
                .addAsWebInfResource(new StringAsset("test-realm { " + MockLoginModule.class.getName() + " required; };"), "classes/jaas.config")
                .addAsManifestResource(new ClassLoaderAsset("META-INF/all.xml"), "context.xml");

    }

    @ArquillianResource
    private URL webapp;

    @Test
    public void feature() throws Exception {

        final WebClient webClient = WebClient.create(
                webapp.toExternalForm(),
                Collections.emptyList(),
                Collections.<AbstractFeature>singletonList(new SecurityFeature(
                        DIGEST_ALGORITHM,
                        KeystoreInitializer.SECRET,
                        KeystoreInitializer.KEY_ALIAS,
                        KeystoreInitializer.ALGO,
                        SIGNATURE_HEADERS)),
                null);

        final String actual = webClient
                .path("api/colors")
                .path("preferred")
                .get(String.class);

        assertEquals("orange", actual);
    }
}
