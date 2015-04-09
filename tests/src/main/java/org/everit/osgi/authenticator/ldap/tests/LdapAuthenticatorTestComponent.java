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

/**
 * Integration test component of the LdapAuthenticatorComponent.
 */
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
