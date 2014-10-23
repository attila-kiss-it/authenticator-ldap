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
import org.osgi.framework.BundleContext;
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
        @Property(name = LdapAuthenticatorConstants.PROP_BASE_DN),
        @Property(name = LdapAuthenticatorConstants.PROP_SEARCH_BASE),
        @Property(name = LdapAuthenticatorConstants.PROP_USER_DN_TEMPLATE),
        @Property(name = LdapAuthenticatorConstants.PROP_LOG_SERVICE)
})
@Service
public class LdapAuthenticatorComponent implements Authenticator {

    @Reference(bind = "setLogService")
    private LogService logService;

    private String searchBase;

    private String baseDn;

    private String userDnPrefix;

    private String userDnSuffix;

    private LdapContextFactory ldapContextFactory;

    @Activate
    public void activate(final BundleContext context, final Map<String, Object> componentProperties)
            throws ConfigurationException {
        String url =
                getStringProperty(componentProperties, LdapAuthenticatorConstants.PROP_URL);
        String systemUsername =
                getStringProperty(componentProperties, LdapAuthenticatorConstants.PROP_SYSTEM_USERNAME);
        String systemPassword =
                getStringProperty(componentProperties, LdapAuthenticatorConstants.PROP_SYSTEM_PASSWORD);
        baseDn =
                getStringProperty(componentProperties, LdapAuthenticatorConstants.PROP_BASE_DN);
        searchBase =
                getStringProperty(componentProperties, LdapAuthenticatorConstants.PROP_SEARCH_BASE);
        String userDnTemplate =
                getStringProperty(componentProperties, LdapAuthenticatorConstants.PROP_USER_DN_TEMPLATE);
        initUserDnPrefixAndSuffix(userDnTemplate);

        ldapContextFactory = new DefaultLdapContextFactory(url,
                LdapAuthenticatorConstants.SIMPLE_AUTHENTICATION_MECHANISM,
                systemUsername, systemPassword, true,
                LdapAuthenticatorConstants.DEFAULT_CONTEXT_FACTORY_CLASS_NAME,
                LdapAuthenticatorConstants.DEFAULT_TIMEOUT_MS,
                LdapAuthenticatorConstants.REFERRAL_FOLLOW);
    }

    @Override
    public Optional<String> authenticate(final String principal, final String credential) {
        try {
            String cn = queryCnByPrincipal(principal);
            String userDn = userDnPrefix + cn + userDnSuffix;

            // if the LdapContext is created successfully, then the user is authenticated
            ldapContextFactory.getLdapContext(userDn, credential);

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

    /**
     * Sets the User Distinguished Name (DN) template to use when creating User DNs at runtime. A User DN is an LDAP
     * fully-qualified unique user identifier which is required to establish a connection with the LDAP directory to
     * authenticate users and query for authorization information. <h2>Usage</h2> User DN formats are unique to the LDAP
     * directory's schema, and each environment differs - you will need to specify the format corresponding to your
     * directory. You do this by specifying the full User DN as normal, but but you use a <b>{@code 0} </b> placeholder
     * token in the string representing the location where the user's submitted principal (usually a username or uid)
     * will be substituted at runtime.
     * <p/>
     * For example, if your directory uses an LDAP {@code uid} attribute to represent usernames, the User DN for the
     * {@code jsmith} user may look like this:
     * <p/>
     *
     * <pre>
     * uid=jsmith,ou=users,dc=mycompany,dc=com
     * </pre>
     * <p/>
     * in which case you would set this property with the following template value:
     * <p/>
     *
     * <pre>
     * uid=<b>{0}</b>,ou=users,dc=mycompany,dc=com
     * </pre>
     * <p/>
     * If no template is configured, the raw {@code AuthenticationToken} {@link AuthenticationToken#getPrincipal()
     * principal} will be used as the LDAP principal. This is likely incorrect as most LDAP directories expect a
     * fully-qualified User DN as opposed to the raw uid or username. So, ensure you set this property to match your
     * environment!
     *
     * @param template
     *            the User Distinguished Name template to use for runtime substitution
     * @throws IllegalArgumentException
     *             if the template is null, empty, or does not contain the {@code 0} substitution token.
     * @see LdapContextFactory#getLdapContext(Object,Object)
     */
    public void initUserDnPrefixAndSuffix(final String template) throws IllegalArgumentException {
        if (template.trim().isEmpty()) {
            throw new IllegalArgumentException("User DN template cannot be empty.");
        }
        int index = template.indexOf(LdapAuthenticatorConstants.USERDN_SUBSTITUTION_TOKEN);
        if (index < 0) {
            throw new IllegalArgumentException("User DN template must contain the '" +
                    LdapAuthenticatorConstants.USERDN_SUBSTITUTION_TOKEN
                    + "' replacement token to understand where to " +
                    "insert the runtime authentication principal.");
        }
        String prefix = template.substring(0, index);
        String suffix = template.substring(prefix.length()
                + LdapAuthenticatorConstants.USERDN_SUBSTITUTION_TOKEN.length());

        userDnPrefix = prefix;
        userDnSuffix = suffix;
    }

    private String queryCnByPrincipal(final Object principal) throws NamingException {
        LdapContext systemLdapContext = null;
        NamingEnumeration<SearchResult> namingEnumeration = null;
        try {
            systemLdapContext = ldapContextFactory.getSystemLdapContext();
            namingEnumeration = systemLdapContext.search(baseDn, searchBase, new Object[] { principal }, null);
            if (!namingEnumeration.hasMoreElements()) {
                throw new NamingException("No result for "
                        + "baseDn [" + baseDn + "] searchBase [" + searchBase + "] with principal [" + principal + "]");
            }
            SearchResult searchResult = namingEnumeration.nextElement();
            if (namingEnumeration.hasMoreElements()) {
                throw new NamingException(
                        "More than one result for searchBase [" + searchBase + "] with principal [" + principal + "]");
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
