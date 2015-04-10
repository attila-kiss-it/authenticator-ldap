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
package org.everit.osgi.authenticator.ldap.internal;

import java.util.Map;
import java.util.Optional;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;

import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.ConfigurationPolicy;
import org.apache.felix.scr.annotations.Properties;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.Service;
import org.everit.osgi.authenticator.Authenticator;
import org.everit.osgi.authenticator.ldap.LdapAuthenticatorConstants;
import org.everit.osgi.authenticator.ldap.LdapContextFactory;
import org.osgi.framework.Constants;
import org.osgi.service.cm.ConfigurationException;
import org.osgi.service.log.LogService;

/**
 * An {@link Authenticator} that authenticates users on LDAP protocol.
 */
@Component(name = LdapAuthenticatorConstants.SERVICE_FACTORYPID_LDAP_AUTHENTICATOR,
    metatype = true,
    configurationFactory = true, policy = ConfigurationPolicy.REQUIRE)
@Properties({
    @Property(name = Constants.SERVICE_DESCRIPTION, propertyPrivate = false,
        value = LdapAuthenticatorConstants.DEFAULT_SERVICE_DESCRIPTION_LDAP_AUTHENTICATOR),
    @Property(name = LdapAuthenticatorConstants.PROP_SSL_ENABLED, boolValue = false),
    @Property(name = LdapAuthenticatorConstants.PROP_LDAP_URL),
    @Property(name = LdapAuthenticatorConstants.PROP_SYSTEM_USER_DN),
    @Property(name = LdapAuthenticatorConstants.PROP_SYSTEM_USER_PASSWORD),
    @Property(name = LdapAuthenticatorConstants.PROP_USER_BASE_DN),
    @Property(name = LdapAuthenticatorConstants.PROP_USER_SEARCH_BASE),
    @Property(name = LdapAuthenticatorConstants.PROP_USER_DN_TEMPLATE),
    @Property(name = LdapAuthenticatorConstants.PROP_LOG_SERVICE) })
@Service
public class LdapAuthenticatorComponent implements Authenticator {

  // The zero index currently means nothing, but could be utilized in the future for other
  // substitution techniques.
  private static final String SUBSTITUTION_TOKEN = "{0}";

  private LdapContextFactory ldapContextFactory;

  @Reference(bind = "setLogService")
  private LogService logService;

  private String userBaseDn;

  private String userDnPrefix;

  private String userDnSuffix;

  private String userSearchBase;

  /**
   * Initializes the OSGi component based on the component configuration.
   */
  @Activate
  public void activate(final Map<String, Object> componentProperties)
      throws ConfigurationException {
    boolean sslEnabled = (boolean)
        componentProperties.get(LdapAuthenticatorConstants.PROP_SSL_ENABLED);
    String ldapUrl = getStringProperty(
        componentProperties, LdapAuthenticatorConstants.PROP_LDAP_URL);
    String systemUserDn = getStringProperty(
        componentProperties, LdapAuthenticatorConstants.PROP_SYSTEM_USER_DN);
    String systemUserPassword = getStringProperty(
        componentProperties, LdapAuthenticatorConstants.PROP_SYSTEM_USER_PASSWORD);
    userBaseDn = getStringProperty(
        componentProperties, LdapAuthenticatorConstants.PROP_USER_BASE_DN);
    userSearchBase = getStringProperty(
        componentProperties, LdapAuthenticatorConstants.PROP_USER_SEARCH_BASE);
    String userDnTemplate = getStringProperty(
        componentProperties, LdapAuthenticatorConstants.PROP_USER_DN_TEMPLATE);
    initUserDnPrefixAndSuffix(userDnTemplate);

    ldapContextFactory =
        new LdapContextFactory(sslEnabled, ldapUrl, systemUserDn, systemUserPassword, null);
  }

  @Override
  public Optional<String> authenticate(final String principal, final String credential) {
    try {
      String cn = queryCnByPrincipal(principal);
      String userDn = userDnPrefix + cn + userDnSuffix;

      // if the LdapContext is created successfully, then the user is authenticated
      ldapContextFactory.createLdapContext(userDn, credential);

      return Optional.of(userDn);
    } catch (NamingException e) {
      logService.log(LogService.LOG_WARNING, "Failed to query cn", e);
      return Optional.empty();
    }
  }

  private String getStringProperty(final Map<String, Object> componentProperties,
      final String propertyName)
      throws ConfigurationException {
    Object value = componentProperties.get(propertyName);
    if (value == null) {
      throw new ConfigurationException(propertyName, "property not defined");
    }
    return String.valueOf(value);
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
        logService.log(LogService.LOG_ERROR, "Exception while closing LDAP context. ", e);
      }
      try {
        if (namingEnumeration != null) {
          namingEnumeration.close();
        }
      } catch (Exception e) {
        logService.log(LogService.LOG_ERROR, "Failed to close naming enumeration", e);
      }
    }
  }

  public void setLogService(final LogService logService) {
    this.logService = logService;
  }

}
