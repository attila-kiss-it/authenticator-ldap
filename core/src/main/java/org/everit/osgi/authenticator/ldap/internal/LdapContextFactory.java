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

import javax.naming.AuthenticationException;
import javax.naming.NamingException;
import javax.naming.ldap.LdapContext;

public interface LdapContextFactory {

    LdapContext getLdapContext(String userDn, String credential) throws AuthenticationException, NamingException;

    LdapContext getSystemLdapContext() throws AuthenticationException, NamingException;

}
