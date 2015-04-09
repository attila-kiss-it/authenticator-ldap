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
package org.everit.osgi.authenticator.ldap;

/**
 * Constants used by the LdapAuthenticatorComponent OSGi Component.
 */
public final class LdapAuthenticatorConstants {

  public static final String DEFAULT_SERVICE_DESCRIPTION_LDAP_AUTHENTICATOR =
      "Default LDAP Authenticator Component";

  public static final String PROP_LDAP_URL = "ldapUrl";

  public static final String PROP_LOG_SERVICE = "logService.target";

  public static final String PROP_SSL_ENABLED = "sslEnabled";

  public static final String PROP_SYSTEM_USER_DN = "systemUserDn";

  public static final String PROP_SYSTEM_USER_PASSWORD = "systemUserPassword";

  public static final String PROP_USER_BASE_DN = "userBaseDn";

  public static final String PROP_USER_DN_TEMPLATE = "userDnTemplate";

  public static final String PROP_USER_SEARCH_BASE = "userSearchBase";

  public static final String SERVICE_FACTORYPID_LDAP_AUTHENTICATOR =
      "org.everit.osgi.authenticator.ldap.LdapAuthenticator";

  private LdapAuthenticatorConstants() {
  }

}
