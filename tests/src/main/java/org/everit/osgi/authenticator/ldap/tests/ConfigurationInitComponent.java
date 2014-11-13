/**
 * This file is part of Everit - LDAP Authenticator tests.
 *
 * Everit - LDAP Authenticator tests is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Everit - LDAP Authenticator tests is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Everit - LDAP Authenticator tests.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.everit.osgi.authenticator.ldap.tests;

import java.io.IOException;
import java.util.Dictionary;
import java.util.Hashtable;

import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Properties;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.Service;
import org.everit.osgi.authenticator.ldap.LdapAuthenticatorConstants;
import org.osgi.service.cm.Configuration;
import org.osgi.service.cm.ConfigurationAdmin;

@Component(name = "ConfigurationInit", immediate = true)
@Properties({
        @Property(name = "configurationAdmin.target"),
        @Property(name = "ldapPortProvider.target")
})
@Service(value = ConfigurationInitComponent.class)
public class ConfigurationInitComponent {

    @Reference(bind = "setConfigurationAdmin")
    private ConfigurationAdmin configurationAdmin;

    @Reference(bind = "setLdapPortProvider")
    private LdapPortProvider ldapPortProvider;

    private String ldapAuthenticatorConfigurationPid;

    @Activate
    public void activate() throws IOException {
        Configuration configuration = configurationAdmin.createFactoryConfiguration(
                LdapAuthenticatorConstants.SERVICE_FACTORYPID_LDAP_AUTHENTICATOR, null);
        ldapAuthenticatorConfigurationPid = configuration.getPid();
        Dictionary<String, String> properties = new Hashtable<>();
        properties.put(LdapAuthenticatorConstants.PROP_URL, "ldap://localhost:" + ldapPortProvider.getPort());
        properties.put(LdapAuthenticatorConstants.PROP_SYSTEM_USER_DN, "uid=admin,ou=system");
        properties.put(LdapAuthenticatorConstants.PROP_SYSTEM_USER_PASSWORD, "secret");
        properties.put(LdapAuthenticatorConstants.PROP_USER_BASE_DN, "ou=people,o=sevenSeas");
        properties.put(LdapAuthenticatorConstants.PROP_USER_SEARCH_BASE, "mail={0}");
        properties.put(LdapAuthenticatorConstants.PROP_USER_DN_TEMPLATE, "cn={0},ou=people,o=sevenSeas");
        configuration.update(properties);
    }

    @Deactivate
    public void deactivate() throws IOException {
        Configuration configuration = configurationAdmin.getConfiguration(ldapAuthenticatorConfigurationPid);
        configuration.delete();
    }

    public void setConfigurationAdmin(final ConfigurationAdmin configurationAdmin) {
        this.configurationAdmin = configurationAdmin;
    }

    public void setLdapPortProvider(final LdapPortProvider ldapPortProvider) {
        this.ldapPortProvider = ldapPortProvider;
    }

}
