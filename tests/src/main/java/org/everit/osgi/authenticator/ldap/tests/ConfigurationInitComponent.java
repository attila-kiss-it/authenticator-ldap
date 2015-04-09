/*
 * Copyright (C) 2011 Everit Kft. (http://www.everit.org)
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

  private String ldapAuthenticatorConfigurationPid;

  @Reference(bind = "setLdapPortProvider")
  private LdapPortProvider ldapPortProvider;

  @Activate
  public void activate() throws IOException {
    Configuration configuration = configurationAdmin.createFactoryConfiguration(
        LdapAuthenticatorConstants.SERVICE_FACTORYPID_LDAP_AUTHENTICATOR, null);
    ldapAuthenticatorConfigurationPid = configuration.getPid();
    Dictionary<String, String> properties = new Hashtable<>();
    properties.put(LdapAuthenticatorConstants.PROP_URL,
        "ldap://localhost:" + ldapPortProvider.getPort());
    properties.put(LdapAuthenticatorConstants.PROP_SYSTEM_USER_DN, "uid=admin,ou=system");
    properties.put(LdapAuthenticatorConstants.PROP_SYSTEM_USER_PASSWORD, "secret");
    properties.put(LdapAuthenticatorConstants.PROP_USER_BASE_DN, "ou=people,o=sevenSeas");
    properties.put(LdapAuthenticatorConstants.PROP_USER_SEARCH_BASE, "mail={0}");
    properties
        .put(LdapAuthenticatorConstants.PROP_USER_DN_TEMPLATE, "cn={0},ou=people,o=sevenSeas");
    configuration.update(properties);
  }

  @Deactivate
  public void deactivate() throws IOException {
    Configuration configuration = configurationAdmin
        .getConfiguration(ldapAuthenticatorConfigurationPid);
    configuration.delete();
  }

  public void setConfigurationAdmin(final ConfigurationAdmin configurationAdmin) {
    this.configurationAdmin = configurationAdmin;
  }

  public void setLdapPortProvider(final LdapPortProvider ldapPortProvider) {
    this.ldapPortProvider = ldapPortProvider;
  }

}
