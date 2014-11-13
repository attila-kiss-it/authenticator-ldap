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

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;

public class InitialLdapContextFactory {

    private static final String DEFAULT_CONTEXT_FACTORY_CLASS_NAME = "com.sun.jndi.ldap.LdapCtxFactory";

    private static final String DEFAULT_CONNECTION_POOLING_ENV_PROP = "com.sun.jndi.ldap.connect.pool";

    private static final String DEFAULT_POOLING_ENABLED = Boolean.TRUE.toString();

    private static final String DEFAULT_LDAP_READ_TIMEOUT_ENV_PROP = "com.sun.jndi.ldap.read.timeout";

    private static final String DEFAULT_TIMEOUT_MS = "10000";

    private static final String SIMPLE_AUTHENTICATION_MECHANISM = "simple";

    private static final String REFERRAL_FOLLOW = "follow";

    private final String url;

    private final String systemUserDn;

    private final String systemUserPassword;

    public InitialLdapContextFactory(final String url, final String systemUserDn, final String systemUserPassword) {
        this.url = url;
        this.systemUserDn = systemUserDn;
        this.systemUserPassword = systemUserPassword;
    }

    private Hashtable<String, Object> createEnvironment(final String userDn, final String userPassword)
            throws AuthenticationException {
        Hashtable<String, Object> environment = new Hashtable<>();
        environment.put(Context.PROVIDER_URL, url);
        environment.put(Context.SECURITY_AUTHENTICATION, SIMPLE_AUTHENTICATION_MECHANISM);
        environment.put(Context.SECURITY_PRINCIPAL, userDn);
        environment.put(Context.SECURITY_CREDENTIALS, userPassword);
        environment.put(Context.INITIAL_CONTEXT_FACTORY, DEFAULT_CONTEXT_FACTORY_CLASS_NAME);
        environment.put(DEFAULT_LDAP_READ_TIMEOUT_ENV_PROP, DEFAULT_TIMEOUT_MS);
        environment.put(Context.REFERRAL, REFERRAL_FOLLOW);
        environment.put(DEFAULT_CONNECTION_POOLING_ENV_PROP, DEFAULT_POOLING_ENABLED);
        return environment;
    }

    public LdapContext getLdapContext(final String userDn, final String password) throws NamingException {
        Hashtable<String, Object> env = createEnvironment(userDn, password);
        return new InitialLdapContext(env, null);
    }

    public LdapContext getSystemLdapContext() throws NamingException {
        return getLdapContext(systemUserDn, systemUserPassword);
    }

}
