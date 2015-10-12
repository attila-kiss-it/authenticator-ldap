/*
 * Copyright (C) 2011 Everit Kft. (http://www.everit.biz)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.everit.authenticator.ldap;

import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;

/**
 * Factory for creating {@link LdapContext} and authenticate users based on the configured LDAP
 * protocol.
 */
public class LdapContextFactory {

  private static final String DEFAULT_CONNECTION_POOLING_ENV_PROP =
      "com.sun.jndi.ldap.connect.pool";

  private static final String DEFAULT_CONTEXT_FACTORY_CLASS_NAME =
      "com.sun.jndi.ldap.LdapCtxFactory";

  private static final String DEFAULT_LDAP_READ_TIMEOUT_ENV_PROP =
      "com.sun.jndi.ldap.read.timeout";

  private static final String DEFAULT_POOLING_ENABLED = Boolean.TRUE.toString();

  private static final String DEFAULT_TIMEOUT_MS = "10000";

  private static final String REFERRAL_FOLLOW = "follow";

  private static final String SIMPLE_AUTHENTICATION_MECHANISM = "simple";

  private static final String SSL = "ssl";

  private final Map<String, Object> additionalEnvironment = new HashMap<String, Object>();

  private final String ldapUrl;

  private final boolean sslEnabled;

  private final String systemUserDn;

  private final String systemUserPassword;

  /**
   * Constructor.
   *
   * @param sslEnabled
   *          SSL security protocol used or not
   * @param ldapUrl
   *          the LDAP URL to connect to
   * @param systemUserDn
   *          the DN of the system user
   * @param systemUserPassword
   *          the password of the system user
   * @param additionalEnvironment
   *          additional environment properties that may override default settings
   */
  public LdapContextFactory(final boolean sslEnabled, final String ldapUrl,
      final String systemUserDn, final String systemUserPassword,
      final Map<String, Object> additionalEnvironment) {
    this.sslEnabled = sslEnabled;
    this.ldapUrl = ldapUrl;
    this.systemUserDn = systemUserDn;
    this.systemUserPassword = systemUserPassword;
    if (additionalEnvironment != null) {
      this.additionalEnvironment.putAll(additionalEnvironment);
    }
  }

  private Hashtable<String, Object> createEnvironment(final String userDn,
      final String userPassword) throws AuthenticationException {
    Hashtable<String, Object> environment = new Hashtable<>();
    environment.put(Context.PROVIDER_URL, ldapUrl);
    environment.put(Context.SECURITY_AUTHENTICATION, SIMPLE_AUTHENTICATION_MECHANISM);
    environment.put(Context.SECURITY_PRINCIPAL, userDn);
    environment.put(Context.SECURITY_CREDENTIALS, userPassword);
    environment.put(Context.INITIAL_CONTEXT_FACTORY, DEFAULT_CONTEXT_FACTORY_CLASS_NAME);
    environment.put(DEFAULT_LDAP_READ_TIMEOUT_ENV_PROP, DEFAULT_TIMEOUT_MS);
    environment.put(Context.REFERRAL, REFERRAL_FOLLOW);
    environment.put(DEFAULT_CONNECTION_POOLING_ENV_PROP, DEFAULT_POOLING_ENABLED);
    if (sslEnabled) {
      environment.put(Context.SECURITY_PROTOCOL, SSL);
    }
    environment.putAll(additionalEnvironment);
    return environment;
  }

  public LdapContext createLdapContext(final String userDn, final String password)
      throws NamingException {
    Hashtable<String, Object> env = createEnvironment(userDn, password);
    return new InitialLdapContext(env, null);
  }

  public LdapContext createSystemLdapContext() throws NamingException {
    return createLdapContext(systemUserDn, systemUserPassword);
  }

}
