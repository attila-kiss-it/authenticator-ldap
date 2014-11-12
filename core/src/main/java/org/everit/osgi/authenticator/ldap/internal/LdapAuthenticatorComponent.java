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

import java.util.Map;
import java.util.Optional;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
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
import org.osgi.framework.Constants;
import org.osgi.service.cm.ConfigurationException;
import org.osgi.service.log.LogService;

@Component(name = LdapAuthenticatorConstants.SERVICE_FACTORYPID_LDAP_AUTHENTICATOR, metatype = true,
        configurationFactory = true, policy = ConfigurationPolicy.REQUIRE)
@Properties({
        @Property(name = Constants.SERVICE_DESCRIPTION, propertyPrivate = false,
                value = LdapAuthenticatorConstants.DEFAULT_SERVICE_DESCRIPTION_LDAP_AUTHENTICATOR),
        @Property(name = LdapAuthenticatorConstants.PROP_URL),
        @Property(name = LdapAuthenticatorConstants.PROP_SYSTEM_USERNAME),
        @Property(name = LdapAuthenticatorConstants.PROP_SYSTEM_PASSWORD),
        @Property(name = LdapAuthenticatorConstants.PROP_USER_BASE_DN),
        @Property(name = LdapAuthenticatorConstants.PROP_USER_SEARCH_BASE),
        @Property(name = LdapAuthenticatorConstants.PROP_USER_DN_TEMPLATE),
        @Property(name = LdapAuthenticatorConstants.PROP_LOG_SERVICE)
})
@Service
public class LdapAuthenticatorComponent implements Authenticator {

    // The zero index currently means nothing, but could be utilized in the future for other substitution techniques.
    private static final String SUBSTITUTION_TOKEN = "{0}";

    @Reference(bind = "setLogService")
    private LogService logService;

    private String userSearchBase;

    private String userBaseDn;

    private String userDnPrefix;

    private String userDnSuffix;

    private InitialLdapContextFactory initialLdapContextFactory;

    @Activate
    public void activate(final Map<String, Object> componentProperties) throws ConfigurationException {
        String url =
                getStringProperty(componentProperties, LdapAuthenticatorConstants.PROP_URL);
        String systemUsername =
                getStringProperty(componentProperties, LdapAuthenticatorConstants.PROP_SYSTEM_USERNAME);
        String systemPassword =
                getStringProperty(componentProperties, LdapAuthenticatorConstants.PROP_SYSTEM_PASSWORD);
        userBaseDn =
                getStringProperty(componentProperties, LdapAuthenticatorConstants.PROP_USER_BASE_DN);
        userSearchBase =
                getStringProperty(componentProperties, LdapAuthenticatorConstants.PROP_USER_SEARCH_BASE);
        String userDnTemplate =
                getStringProperty(componentProperties, LdapAuthenticatorConstants.PROP_USER_DN_TEMPLATE);
        initUserDnPrefixAndSuffix(userDnTemplate);

        initialLdapContextFactory = new InitialLdapContextFactory(url, systemUsername, systemPassword);
    }

    @Override
    public Optional<String> authenticate(final String principal, final String credential) {
        try {
            String cn = queryCnByPrincipal(principal);
            String userDn = userDnPrefix + cn + userDnSuffix;

            // if the LdapContext is created successfully, then the user is authenticated
            initialLdapContextFactory.getLdapContext(userDn, credential);

            return Optional.of(userDn);
        } catch (NamingException e) {
            logService.log(LogService.LOG_WARNING, "Failed to query cn", e);
            return Optional.empty();
        }
    }

    private String getStringProperty(final Map<String, Object> componentProperties, final String propertyName)
            throws ConfigurationException {
        Object value = componentProperties.get(propertyName);
        if (value == null) {
            throw new ConfigurationException(propertyName, "property not defined");
        }
        return String.valueOf(value);
    }

    public void initUserDnPrefixAndSuffix(final String userDnTemplate)
            throws IllegalArgumentException {
        if (userDnTemplate.trim().isEmpty()) {
            throw new IllegalArgumentException("userDnTemplate cannot be empty.");
        }
        int index = userDnTemplate.indexOf(SUBSTITUTION_TOKEN);
        if (index < 0) {
            throw new IllegalArgumentException("userDnTemplate [" + userDnTemplate + "] must contain the '"
                    + SUBSTITUTION_TOKEN + "' replacement token to understand where"
                    + " to insert the runtime authentication principal.");
        }
        userDnPrefix = userDnTemplate.substring(0, index);
        userDnSuffix = userDnTemplate.substring(userDnPrefix.length() + SUBSTITUTION_TOKEN.length());
    }

    private String queryCnByPrincipal(final Object principal) throws NamingException {
        LdapContext systemLdapContext = null;
        NamingEnumeration<SearchResult> namingEnumeration = null;
        try {
            systemLdapContext = initialLdapContextFactory.getSystemLdapContext();
            namingEnumeration = systemLdapContext.search(userBaseDn, userSearchBase, new Object[] { principal }, null);
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
