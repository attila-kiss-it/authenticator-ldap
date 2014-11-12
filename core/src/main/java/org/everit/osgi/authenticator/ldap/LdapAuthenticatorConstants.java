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
package org.everit.osgi.authenticator.ldap;

public final class LdapAuthenticatorConstants {

    public static final String SERVICE_FACTORYPID_LDAP_AUTHENTICATOR =
            "org.everit.osgi.authenticator.ldap.LdapAuthenticator";

    public static final String DEFAULT_SERVICE_DESCRIPTION_LDAP_AUTHENTICATOR =
            "Default LDAP Authenticator Component";

    /**
     * The LDAP URL to connect to. (e.g. ldap://&lt;ldapDirectoryHostname&gt;:&lt;port&gt;)
     */
    public static final String PROP_URL = "url";

    public static final String PROP_SYSTEM_USERNAME = "systemUsername";

    public static final String PROP_SYSTEM_PASSWORD = "systemPassword";

    public static final String PROP_SUBSTITUTION_TOKEN = "substitutionToken";

    // The zero index currently means nothing, but could be utilized in the future for other substitution techniques.
    public static final String DEFAULT_SUBSTITUTION_TOKEN = "{0}";

    public static final String PROP_USER_DN_TEMPLATE = "userDnTemplate";

    public static final String PROP_BASE_DN = "baseDn";

    public static final String PROP_SEARCH_BASE = "searchBase";

    public static final String PROP_LOG_SERVICE = "logService.target";

    private LdapAuthenticatorConstants() {
    }

}
