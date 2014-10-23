/**
 * This file is part of Everit - LDAP Authenticator.
 *
 * Everit - LDAP Authenticator is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Everit - LDAP Authenticator is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Everit - LDAP Authenticator.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.everit.osgi.authenticator.ldap.internal;

import java.util.Hashtable;
import java.util.Map;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;

import org.everit.osgi.authenticator.ldap.LdapAuthenticatorConstants;

public class DefaultLdapContextFactory implements LdapContextFactory {

    private final String url;

    private final String authenticationMechanism;

    private final String systemUserDn;

    private final String systemPassword;

    private final String poolingEnabled;

    private final String contextFactoryClassName;

    private final String timeoutMs;

    private final String referral;

    /**
     *
     * @param url
     *            The LDAP URL to connect to. (e.g. ldap://&lt;ldapDirectoryHostname&gt;:&lt;port&gt;)
     * @param authenticationMechanism
     * @param systemUserDn
     * @param systemPassword
     * @param poolingEnabled
     * @param timeoutMs
     * @throws AuthenticationException
     */
    public DefaultLdapContextFactory(final String url, final String authenticationMechanism,
            final String systemUserDn, final String systemPassword, final boolean poolingEnabled,
            final String contextFactoryClassName, final long timeoutMs, final String referral) {
        if (!contextFactoryClassName.equals(LdapAuthenticatorConstants.DEFAULT_CONTEXT_FACTORY_CLASS_NAME)) {
            throw new IllegalArgumentException(contextFactoryClassName + " not supported, use ["
                    + LdapAuthenticatorConstants.DEFAULT_CONTEXT_FACTORY_CLASS_NAME + "]");
        }
        this.url = url;
        this.authenticationMechanism = authenticationMechanism;
        this.systemUserDn = systemUserDn;
        this.systemPassword = systemPassword;
        this.poolingEnabled = Boolean.valueOf(poolingEnabled).toString();
        this.contextFactoryClassName = contextFactoryClassName;
        this.timeoutMs = String.valueOf(timeoutMs);
        this.referral = referral;
    }

    private Hashtable<String, Object> createEnvironment(final String userDn, final String credential)
            throws AuthenticationException {
        Hashtable<String, Object> environment = new Hashtable<>();
        environment.put(Context.PROVIDER_URL, url);
        environment.put(Context.SECURITY_AUTHENTICATION, authenticationMechanism);
        environment.put(Context.SECURITY_PRINCIPAL, userDn);
        environment.put(Context.SECURITY_CREDENTIALS, credential);
        environment.put(Context.INITIAL_CONTEXT_FACTORY, contextFactoryClassName);
        environment.put(LdapAuthenticatorConstants.DEFAULT_LDAP_READ_TIMEOUT_ENV_PROP, timeoutMs);
        environment.put(Context.REFERRAL, referral);
        environment.put(LdapAuthenticatorConstants.DEFAULT_CONNECTION_POOLING_ENV_PROP, poolingEnabled);
        validateEnvironment(environment);
        return environment;
    }

    @Override
    public LdapContext getLdapContext(final String userDn, final String credential) throws NamingException {
        Hashtable<String, Object> env = createEnvironment(userDn, credential);
        return new InitialLdapContext(env, null);
    }

    @Override
    public LdapContext getSystemLdapContext() throws NamingException {
        return getLdapContext(systemUserDn, systemPassword);
    }

    /**
     * Validates the configuration in the JNDI <code>environment</code> settings and throws an exception if a problem
     * exists.
     * <p/>
     * This implementation will throw a {@link AuthenticationException} if the authentication mechanism is set to
     * 'simple', the principal is non-empty, and the credentials are empty (as per <a
     * href="http://tools.ietf.org/html/rfc4513#section-5.1.2">rfc4513 section-5.1.2</a>).
     *
     * @param environment
     *            the JNDI environment settings to be validated
     * @throws AuthenticationException
     *             if a configuration problem is detected
     */
    private void validateEnvironment(final Map<String, Object> environment)
            throws AuthenticationException {
        // validate when using Simple auth both principal and credentials are set
        if (LdapAuthenticatorConstants.SIMPLE_AUTHENTICATION_MECHANISM.equals(
                environment.get(Context.SECURITY_AUTHENTICATION))) {

            // only validate credentials if we have a non-empty principal
            Object principal = environment.get(Context.SECURITY_PRINCIPAL);
            if ((principal != null) && !String.valueOf(principal).trim().isEmpty()) {

                Object credentials = environment.get(Context.SECURITY_CREDENTIALS);

                // from the FAQ, we need to check for empty credentials:
                // http://docs.oracle.com/javase/tutorial/jndi/ldap/faq.html
                if ((credentials == null) ||
                        ((credentials instanceof byte[]) && (((byte[]) credentials).length <= 0)) || // empty byte[]
                        ((credentials instanceof char[]) && (((char[]) credentials).length <= 0)) || // empty char[]
                        (String.class.isInstance(credentials) && String.valueOf(credentials).trim().isEmpty())) {

                    throw new AuthenticationException(
                            "LDAP Simple authentication requires both a principal and credentials.");
                }
            }
        }
    }

}
