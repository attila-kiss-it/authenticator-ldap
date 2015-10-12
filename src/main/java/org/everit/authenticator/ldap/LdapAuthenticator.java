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

import java.util.Objects;
import java.util.Optional;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;

import org.everit.authenticator.Authenticator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An {@link Authenticator} that authenticates users on LDAP protocol.
 */
public class LdapAuthenticator implements Authenticator {

  private static final Logger LOGGER = LoggerFactory.getLogger(LdapAuthenticator.class);

  // The zero index currently means nothing, but could be utilized in the future for other
  // substitution techniques.
  private static final String SUBSTITUTION_TOKEN = "{0}";

  private LdapContextFactory ldapContextFactory;

  private String userBaseDn;

  private String userDnPrefix;

  private String userDnSuffix;

  private String userSearchBase;

  /**
   * Constructor that initializes class.
   *
   * @param sslEnabled
   *          SSL security protocol used or not.
   * @param ldapUrl
   *          the LDAP URL to connect to
   * @param systemUserDn
   *          the DN of the system user.
   * @param systemUserPassword
   *          the password of the system user
   * @param userBaseDn
   *          the base DN of the users to search for. (e.g. ou=people,o=sevenSeas).
   * @param userSearchBase
   *          the filter expression to use for the search. Must contain exactly one substitution
   *          token '{0}' that will be replaced by the users principal. (e.g. mail={0}).
   * @param userDnTemplate
   *          the DN template used to create user DN if its authentication succeeds. Must contain
   *          exactly one substitution token '{0}' that will be replaced by the CN of the
   *          authenticated user. (e.g. cn={0},ou=people,o=sevenSeas).
   */
  public LdapAuthenticator(final boolean sslEnabled, final String ldapUrl,
      final String systemUserDn, final String systemUserPassword, final String userBaseDn,
      final String userSearchBase, final String userDnTemplate) {
    this.userBaseDn = Objects.requireNonNull(userBaseDn, "userBaseDn cannot be null");
    this.userSearchBase = Objects.requireNonNull(userSearchBase, "userSearchBase cannot be null");
    Objects.requireNonNull(userDnTemplate, "userDnTemplate cannot be null");
    initUserDnPrefixAndSuffix(userDnTemplate);

    Objects.requireNonNull(ldapUrl, "userDnTemplate cannot be null");
    Objects.requireNonNull(systemUserDn, "userDnTemplate cannot be null");
    Objects.requireNonNull(systemUserPassword, "userDnTemplate cannot be null");
    ldapContextFactory =
        new LdapContextFactory(sslEnabled, ldapUrl, systemUserDn, systemUserPassword, null);
  }

  @Override
  public Optional<String> authenticate(final String principal, final String credential) {

    String trimmedPrincipal = validateArgs(principal, credential);

    try {
      String cn = queryCnByPrincipal(trimmedPrincipal);
      String userDn = userDnPrefix + cn + userDnSuffix;

      // if the LdapContext is created successfully, then the user is authenticated
      ldapContextFactory.createLdapContext(userDn, credential);

      return Optional.of(userDn);
    } catch (NamingException e) {
      LOGGER.warn("Failed to query cn", e);
      return Optional.empty();
    }
  }

  private void initUserDnPrefixAndSuffix(final String userDnTemplate)
      throws IllegalArgumentException {
    if (userDnTemplate.trim().isEmpty()) {
      throw new IllegalArgumentException("userDnTemplate cannot be empty.");
    }
    int index = userDnTemplate.indexOf(SUBSTITUTION_TOKEN);
    if (index < 0) {
      throw new IllegalArgumentException("userDnTemplate [" + userDnTemplate
          + "] must contain the '"
          + SUBSTITUTION_TOKEN + "' replacement token to understand where"
          + " to insert the runtime authentication principal.");
    }
    userDnPrefix = userDnTemplate.substring(0, index);
    userDnSuffix = userDnTemplate.substring(userDnPrefix.length() + SUBSTITUTION_TOKEN.length());
  }

  private String queryCnByPrincipal(final String principal) throws NamingException {
    LdapContext systemLdapContext = null;
    NamingEnumeration<SearchResult> namingEnumeration = null;
    try {
      systemLdapContext = ldapContextFactory.createSystemLdapContext();

      String[] returningAttrs = { "cn" };

      SearchControls searchControls = new SearchControls();
      searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
      searchControls.setReturningAttributes(returningAttrs);

      String filter = userSearchBase.replace(SUBSTITUTION_TOKEN, principal);

      namingEnumeration = systemLdapContext.search(userBaseDn, filter, searchControls);
      if (!namingEnumeration.hasMoreElements()) {
        throw new NamingException("No result for userBaseDn [" + userBaseDn + "] userSearchBase ["
            + userSearchBase + "] with principal [" + principal + "]");
      }
      SearchResult searchResult = namingEnumeration.nextElement();
      if (namingEnumeration.hasMoreElements()) {
        throw new NamingException("More than one result for userSearchBase [" + userSearchBase
            + "] with principal [" + principal + "]");
      }
      Attributes attributes = searchResult.getAttributes();
      Attribute cnAttribute = attributes.get("cn");
      return (String) cnAttribute.get();
    } finally {
      try {
        if (systemLdapContext != null) {
          systemLdapContext.close();
        }
      } catch (NamingException e) {
        LOGGER.error("Exception while closing LDAP context. ", e);
      }
      try {
        if (namingEnumeration != null) {
          namingEnumeration.close();
        }
      } catch (Exception e) {
        LOGGER.error("Failed to close naming enumeration", e);
      }
    }
  }

  private String validateArgs(final String principal, final String credential) {
    if (principal == null) {
      throw new IllegalArgumentException("principal cannot be null");
    }

    String trimmedPrincipal = principal.trim();
    if (trimmedPrincipal.isEmpty()) {
      throw new IllegalArgumentException("principal cannot be empty/blank");
    }

    if (credential == null) {
      throw new IllegalArgumentException("credential cannot be null");
    }

    if (credential.trim().isEmpty()) {
      throw new IllegalArgumentException("credential cannot be empty/blank");
    }

    return trimmedPrincipal;
  }

}
