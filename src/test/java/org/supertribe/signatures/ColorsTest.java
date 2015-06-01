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

import com.tomitribe.auth.signatures.cxf.HttpSignatures;
import com.tomitribe.auth.signatures.cxf.feature.SecurityFeature;
import com.tomitribe.auth.signatures.cxf.feature.DateFeature;
import com.tomitribe.auth.signatures.cxf.feature.DigestFeature;
import com.tomitribe.auth.signatures.cxf.feature.SignatureFeature;
import org.apache.cxf.feature.AbstractFeature;
import org.apache.cxf.jaxrs.client.WebClient;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.ClassLoaderAsset;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.tomitribe.util.IO;

import javax.ws.rs.core.Response;
import java.io.InputStream;
import java.net.URL;
import java.util.Collections;

import static java.util.Arrays.asList;
import static org.junit.Assert.assertEquals;

@RunWith(Arquillian.class)
public class ColorsTest {

    private static final String DIGEST_ALGORITHM = "sha1";
    private static final String SIGNATURE_HEADERS = "(request-target) date";

    /**
     * Build the web archive to test.
     *
     * @return The archive to deploy for the test
     * @throws Exception
     */
    @Deployment(testable = false)
    public static WebArchive war() throws Exception {

        final WebArchive webArchive = ShrinkWrap.create(WebArchive.class, "colors.war")
                .addPackages(true, "org.supertribe.signatures")
                .addAsManifestResource(new ClassLoaderAsset("META-INF/context.xml"), "context.xml");

        System.out.println(webArchive.toString(true));

        return webArchive;
    }

    /**
     * Arquillian will boot an instance of Tribestream with a random port. The URL with the random port is injected
     * into this field.
     */
    @ArquillianResource
    private URL webapp;

    /**
     * Tests accessing a signatures protected method with a GET request
     *
     * @throws Exception when test fails or an error occurs
     */
    @Test
    public void success() throws Exception {

        final WebClient webClient = HttpSignatures.httpSignatureClient(
                webapp.toExternalForm(),
                DIGEST_ALGORITHM,
                KeystoreInitializer.SECRET,
                KeystoreInitializer.ALGO,
                KeystoreInitializer.KEY_ALIAS,
                SIGNATURE_HEADERS);

        final String actual = webClient
                .path("api/colors")
                .path("preferred")
                .get(String.class);

        assertEquals("orange", actual);
    }

    @Test
    public void features() throws Exception {

        final WebClient webClient = WebClient.create(
                webapp.toExternalForm(),
                Collections.emptyList(),
                asList(new SignatureFeature(
                            KeystoreInitializer.SECRET,
                            KeystoreInitializer.KEY_ALIAS,
                            KeystoreInitializer.ALGO,
                            SIGNATURE_HEADERS),
                        new DigestFeature(DIGEST_ALGORITHM),
                        new DateFeature()),
                null);

        final String actual = webClient
                .path("api/colors")
                .path("preferred")
                .get(String.class);

        assertEquals("orange", actual);
    }

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

    /**
     * Tests accessing a signatures protected method with a GET request
     *
     * @throws Exception when test fails or an error occurs
     */
    @Test
    @Ignore
    public void successQueryParams() throws Exception {

        final WebClient webClient = HttpSignatures.httpSignatureClient(
                webapp.toExternalForm(),
                DIGEST_ALGORITHM,
                KeystoreInitializer.SECRET,
                KeystoreInitializer.ALGO,
                KeystoreInitializer.KEY_ALIAS,
                SIGNATURE_HEADERS);

        final String actual = webClient
                .path("api/colors")
                .path("hsb")
                .query("hue", "330")
                .query("saturation", "0.50")
                .query("brightness", "0.80")
                .get(String.class);

        assertEquals("330:0.5:0.8", actual);
    }

    /**
     * Tests accessing a signatures protected method with a POST request
     *
     * @throws Exception when test fails or an error occurs
     */
    @Test
    public void successPost() throws Exception {

        final WebClient webClient = HttpSignatures.httpSignatureClient(
                webapp.toExternalForm(),
                DIGEST_ALGORITHM,
                KeystoreInitializer.SECRET,
                KeystoreInitializer.ALGO,
                KeystoreInitializer.KEY_ALIAS,
                SIGNATURE_HEADERS);

        final String actual = webClient
                .path("api/colors")
                .path("preferred")
                .post("Hello", String.class);

        assertEquals("Hello", actual);
    }

    /**
     * Tests accessing a signatures protected method with a PUT request
     *
     * @throws Exception when test fails or an error occurs
     */
    @Test
    public void successPut() throws Exception {

        final WebClient webClient = HttpSignatures.httpSignatureClient(
                webapp.toExternalForm(),
                DIGEST_ALGORITHM,
                KeystoreInitializer.SECRET,
                KeystoreInitializer.ALGO,
                KeystoreInitializer.KEY_ALIAS,
                SIGNATURE_HEADERS);

        final String actual = webClient
                .path("api/colors")
                .path("preferred")
                .put("World", String.class);

        assertEquals("World", actual);
    }

    /**
     * Tests accessing a signatures protected method with a key that doesn't not have access to the resource
     *
     * @throws Exception when test fails or an error occurs
     */
    @Test
    public void fail() throws Exception {

        final WebClient webClient = HttpSignatures.httpSignatureClient(
                webapp.toExternalForm(),
                DIGEST_ALGORITHM,
                KeystoreInitializer.SECRET,
                KeystoreInitializer.ALGO,
                KeystoreInitializer.KEY_ALIAS,
                SIGNATURE_HEADERS);

        final Response response = webClient
                .path("api/colors")
                .path("refused")
                .get();
        assertEquals(403, response.getStatus());
    }

    /**
     * Tests accessing a signatures protected method with a GET request to a resource that requires a role
     *
     * @throws Exception when test fails or an error occurs
     */
    @Test
    public void authorized() throws Exception {

        final WebClient webClient = HttpSignatures.httpSignatureClient(
                webapp.toExternalForm(),
                DIGEST_ALGORITHM,
                KeystoreInitializer.SECRET,
                KeystoreInitializer.ALGO,
                KeystoreInitializer.KEY_ALIAS,
                SIGNATURE_HEADERS);

        final Response response = webClient
                .path("api/colors")
                .path("authorized")
                .get();
        assertEquals("you rock guys", IO.slurp(InputStream.class.cast(response.getEntity())));
    }
}
