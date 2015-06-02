/*
 * Tomitribe Confidential
 *
 * Copyright Tomitribe Corporation. 2015
 *
 * The source code for this program is not published or otherwise divested
 * of its trade secrets, irrespective of what has been deposited with the
 * U.S. Copyright Office.
 */
package org.supertribe.signatures;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.io.IOException;
import java.util.Map;

public class MockLoginModule implements LoginModule {
    private boolean ok;

    @Override
    public void initialize(final Subject subject, final CallbackHandler callbackHandler,
                           final Map<String, ?> sharedState, final Map<String, ?> options) {
        try {
            final NameCallback name = new NameCallback("name");
            callbackHandler.handle(new Callback[] { name });
            ok = "support".equals(name.getName());
        } catch (final IOException | UnsupportedCallbackException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public boolean login() throws LoginException {
        return ok;
    }

    @Override
    public boolean commit() throws LoginException {
        return true;
    }

    @Override
    public boolean abort() throws LoginException {
        return true;
    }

    @Override
    public boolean logout() throws LoginException {
        return true;
    }
}
