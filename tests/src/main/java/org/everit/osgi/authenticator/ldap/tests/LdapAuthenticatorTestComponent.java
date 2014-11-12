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

import java.nio.file.Files;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import net.sf.ehcache.Cache;
import net.sf.ehcache.CacheManager;
import net.sf.ehcache.config.CacheConfiguration;

import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.schemamanager.impl.DefaultSchemaManager;
import org.apache.directory.server.constants.ServerDNConstants;
import org.apache.directory.server.core.DefaultDirectoryService;
import org.apache.directory.server.core.api.CacheService;
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.core.api.DnFactory;
import org.apache.directory.server.core.api.InstanceLayout;
import org.apache.directory.server.core.api.schema.SchemaPartition;
import org.apache.directory.server.core.partition.impl.btree.jdbm.JdbmIndex;
import org.apache.directory.server.core.partition.impl.btree.jdbm.JdbmPartition;
import org.apache.directory.server.core.shared.DefaultDnFactory;
import org.apache.directory.server.ldap.LdapServer;
import org.apache.directory.server.protocol.shared.transport.TcpTransport;
import org.apache.directory.server.protocol.shared.transport.Transport;
import org.apache.directory.server.xdbm.Index;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Properties;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.Service;
import org.everit.osgi.authenticator.Authenticator;
import org.everit.osgi.dev.testrunner.TestDuringDevelopment;
import org.everit.osgi.dev.testrunner.TestRunnerConstants;
import org.junit.Assert;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.osgi.framework.BundleContext;
import org.osgi.service.log.LogService;

@Component(name = "LdapAuthenticatorTest", immediate = true)
@Properties({
        @Property(name = TestRunnerConstants.SERVICE_PROPERTY_TESTRUNNER_ENGINE_TYPE, value = "junit4"),
        @Property(name = TestRunnerConstants.SERVICE_PROPERTY_TEST_ID, value = "CasAuthenticationTest"),
        @Property(name = "authenticator.target"),
        @Property(name = "logService.target")
})
@Service(value = LdapAuthenticatorTestComponent.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class LdapAuthenticatorTestComponent {

    private static final String CN_FOO = "cn=foo,ou=people,o=sevenSeas";

    private static final String OU_PEOPLE = "ou=people,o=sevenSeas";

    private static final String O_SEVEN_SEAS = "o=sevenSeas";

    private static final String FOO_MAIL = "foo@test.org";

    private static final String FOO_CREDENTIAL = "bar";

    @Reference(bind = "setAuthenticator")
    private Authenticator authenticator;

    @Reference(bind = "setLogService")
    private LogService logService;

    private DirectoryService directoryService;

    private LdapServer ldapServer;

    @Activate
    public void activate(final BundleContext bundleContext, final Map<String, Object> componentProperties)
            throws Exception {
        // Initialize the LDAP service
        directoryService = new DefaultDirectoryService();
        directoryService.setInstanceId("Test Directory Service");

        // Disable the ChangeLog system
        directoryService.getChangeLog().setEnabled(false);
        directoryService.setShutdownHookEnabled(false);
        directoryService.setExitVmOnShutdown(false);
        directoryService.setDenormalizeOpAttrsEnabled(true);
        InstanceLayout instanceLayout = new InstanceLayout(Files.createTempDirectory("directoryService").toFile());
        directoryService.setInstanceLayout(instanceLayout);
        CacheService cacheService = new CacheService(CacheManager.create());
        directoryService.setCacheService(cacheService);

        SchemaManager schemaManager = new DefaultSchemaManager();
        directoryService.setSchemaManager(schemaManager);

        Cache dnCache = new Cache(new CacheConfiguration("wrapped", 100));
        CacheManager cacheManager = CacheManager.newInstance();
        dnCache.setCacheManager(cacheManager);
        dnCache.initialise();
        DnFactory dnFactory = new DefaultDnFactory(schemaManager, dnCache);

        JdbmPartition wrapped = new JdbmPartition(schemaManager, dnFactory);
        wrapped.setPartitionPath(Files.createTempDirectory("wrappedPartition").toFile().toURI());
        wrapped.setId("wrapped");

        SchemaPartition schemaPartition = new SchemaPartition(schemaManager);
        schemaPartition.setWrappedPartition(wrapped);
        directoryService.setSchemaPartition(schemaPartition);

        JdbmPartition systemPartition = new JdbmPartition(schemaManager, dnFactory);
        systemPartition.setId("system");
        systemPartition.setSuffixDn(dnFactory.create(ServerDNConstants.SYSTEM_DN));
        systemPartition.setPartitionPath(Files.createTempDirectory(ServerDNConstants.SYSTEM_DN).toFile().toURI());
        directoryService.setSystemPartition(systemPartition);

        directoryService.startup();

        Dn sevenSeasDn = dnFactory.create(O_SEVEN_SEAS);
        JdbmPartition sevenSeasPartition = addPartition(schemaManager, dnFactory, "sevenSeas", sevenSeasDn);
        addIndex(sevenSeasPartition, "mail");
        if (!directoryService.getAdminSession().exists(sevenSeasDn)) {
            Entry sevenSeasEntry = directoryService.newEntry(sevenSeasDn);
            sevenSeasEntry.add(SchemaConstants.OBJECT_CLASS_AT,
                    SchemaConstants.TOP_OC, SchemaConstants.ORGANIZATION_OC);
            sevenSeasEntry.add(SchemaConstants.O_AT,
                    "sevenSeas");
            directoryService.getAdminSession().add(sevenSeasEntry);
        }

        Dn peopleDn = dnFactory.create(OU_PEOPLE);
        if (!directoryService.getAdminSession().exists(peopleDn)) {
            Entry peopleEntry = directoryService.newEntry(peopleDn);
            peopleEntry.add(SchemaConstants.OBJECT_CLASS_AT,
                    SchemaConstants.TOP_OC, SchemaConstants.ORGANIZATIONAL_UNIT_OC);
            peopleEntry.add(SchemaConstants.OU_AT,
                    "people");
            directoryService.getAdminSession().add(peopleEntry);
        }

        Dn fooDn = dnFactory.create(CN_FOO);
        if (!directoryService.getAdminSession().exists(fooDn)) {
            Entry fooEntry = directoryService.newEntry(fooDn);
            fooEntry.add(SchemaConstants.OBJECT_CLASS_AT,
                    SchemaConstants.TOP_OC, SchemaConstants.PERSON_OC, SchemaConstants.ORGANIZATIONAL_PERSON_OC,
                    SchemaConstants.INET_ORG_PERSON_OC);
            fooEntry.add(SchemaConstants.CN_AT, "foo");
            fooEntry.add(SchemaConstants.SN_AT, "Foo");
            fooEntry.add("mail", FOO_MAIL);
            fooEntry.add(SchemaConstants.USER_PASSWORD_AT, FOO_CREDENTIAL);
            directoryService.getAdminSession().add(fooEntry);
        }

        ldapServer = new LdapServer();
        ldapServer.setDirectoryService(directoryService);

        Transport ldapTransport = new TcpTransport(10389); // TODO use 0 and find out
        ldapServer.setTransports(ldapTransport);

        ldapServer.start();
    }

    private void addIndex(final JdbmPartition partition, final String... attrs) {
        Set<Index<?, String>> indexedAttributes = new HashSet<Index<?, String>>();
        for (String attribute : attrs) {
            indexedAttributes.add(new JdbmIndex<String>(attribute, false));
        }
        partition.setIndexedAttributes(indexedAttributes);
    }

    private JdbmPartition addPartition(final SchemaManager schemaManager, final DnFactory dnFactory,
            final String partitionId, final Dn partitionDn) throws Exception {
        JdbmPartition partition = new JdbmPartition(schemaManager, dnFactory);
        partition.setId(partitionId);
        partition.setSuffixDn(partitionDn);
        partition.setPartitionPath(Files.createTempDirectory(partitionDn.toString()).toFile().toURI());
        partition.initialize();
        directoryService.addPartition(partition);
        return partition;
    }

    @Deactivate
    public void deactivate() throws Exception {
        ldapServer.stop();
        directoryService.shutdown();
        logService.log(LogService.LOG_WARNING, "Waiting 35 seconds for the UnorderedThreadPoolExecutor to shutdown"
                + " gracefully, it is instantiated in the LdapServer.start() method"
                + " with default keep alive 30 seconds.");
        Thread.sleep(35000);
    }

    private void lookup(final String rdn) {
        try {
            Entry result = directoryService.getAdminSession().lookup(new Dn(rdn));
            Assert.assertNotNull(result);
            logService.log(LogService.LOG_INFO, result.toString());
        } catch (LdapException e) {
            Assert.fail(e.getMessage());
        }
    }

    public void setAuthenticator(final Authenticator authenticator) {
        this.authenticator = authenticator;
    }

    public void setLogService(final LogService logService) {
        this.logService = logService;
    }

    @Test
    @TestDuringDevelopment
    public void testAuthenticate() throws Exception {

        lookup(O_SEVEN_SEAS);
        lookup(OU_PEOPLE);
        lookup(CN_FOO);

        String principal = FOO_MAIL;
        String mappedPrincipal = CN_FOO;
        String credential = FOO_CREDENTIAL;

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
