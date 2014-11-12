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

import java.util.Optional;

import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Properties;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.Service;
import org.everit.osgi.authenticator.Authenticator;
import org.everit.osgi.dev.testrunner.TestRunnerConstants;
import org.junit.Assert;
import org.junit.Test;

@Component(name = "LdapAuthenticatorTest", immediate = true)
@Properties({
        @Property(name = TestRunnerConstants.SERVICE_PROPERTY_TESTRUNNER_ENGINE_TYPE, value = "junit4"),
        @Property(name = TestRunnerConstants.SERVICE_PROPERTY_TEST_ID, value = "LdapAuthenticatorTest"),
        @Property(name = "authenticator.target")
})
@Service(value = LdapAuthenticatorTestComponent.class)
public class LdapAuthenticatorTestComponent {

    @Reference(bind = "setAuthenticator")
    private Authenticator authenticator;

    public void setAuthenticator(final Authenticator authenticator) {
        this.authenticator = authenticator;
    }

    @Test
    public void testAuthenticate() throws Exception {
        String principal = LdapTestConstants.FOO_MAIL;
        String mappedPrincipal = LdapTestConstants.CN_FOO;
        String credential = LdapTestConstants.FOO_CREDENTIAL;

        Optional<String> optionalMappedPrincipal = authenticator.authenticate(principal, credential);
        Assert.assertNotNull(optionalMappedPrincipal);
        Assert.assertTrue(optionalMappedPrincipal.isPresent());
        Assert.assertEquals(mappedPrincipal, optionalMappedPrincipal.get());

        optionalMappedPrincipal = authenticator.authenticate(principal, principal);
        Assert.assertNotNull(optionalMappedPrincipal);
        Assert.assertFalse(optionalMappedPrincipal.isPresent());

        optionalMappedPrincipal = authenticator.authenticate(credential, credential);
        Assert.assertNotNull(optionalMappedPrincipal);
        Assert.assertFalse(optionalMappedPrincipal.isPresent());
    }

}
