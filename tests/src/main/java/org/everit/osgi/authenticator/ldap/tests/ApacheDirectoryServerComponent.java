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

import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.util.HashSet;
import java.util.Set;

import net.sf.ehcache.Cache;
import net.sf.ehcache.CacheManager;
import net.sf.ehcache.config.CacheConfiguration;

import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
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
import org.apache.mina.transport.socket.SocketAcceptor;
import org.junit.Assert;
import org.osgi.service.log.LogService;

/**
 * Test AD component.
 */
@Component(name = "ApacheDirectoryServer", immediate = true)
@Properties({
    @Property(name = "logService.target") })
@Service
public class ApacheDirectoryServerComponent implements LdapPortProvider {

  private static final int CACHE_SIZE = 100;

  private static final int SLEEP_TIME = 35000;

  private DirectoryService directoryService;

  private LdapServer ldapServer;

  @Reference(bind = "setLogService")
  private LogService logService;

  private int port;

  /**
   * Initializes and starts the test AD.
   */
  @Activate
  public void activate() throws Exception {
    // Initialize the LDAP service
    directoryService = new DefaultDirectoryService();
    directoryService.setInstanceId("Test Directory Service");

    // Disable the ChangeLog system
    directoryService.getChangeLog().setEnabled(false);
    directoryService.setShutdownHookEnabled(false);
    directoryService.setExitVmOnShutdown(false);
    directoryService.setDenormalizeOpAttrsEnabled(true);
    InstanceLayout instanceLayout = new InstanceLayout(Files
        .createTempDirectory("directoryService").toFile());
    directoryService.setInstanceLayout(instanceLayout);
    CacheService cacheService = new CacheService(CacheManager.create());
    directoryService.setCacheService(cacheService);

    SchemaManager schemaManager = new DefaultSchemaManager();
    directoryService.setSchemaManager(schemaManager);

    Cache dnCache = new Cache(new CacheConfiguration("wrapped", CACHE_SIZE));
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
    systemPartition.setPartitionPath(Files.createTempDirectory(ServerDNConstants.SYSTEM_DN)
        .toFile().toURI());
    directoryService.setSystemPartition(systemPartition);

    directoryService.startup();

    initSevenSeas(schemaManager, dnFactory);

    initPeople(dnFactory);

    initFoo(dnFactory);

    ldapServer = new LdapServer();
    ldapServer.setDirectoryService(directoryService);

    Transport ldapTransport = new TcpTransport(0);
    ldapServer.setTransports(ldapTransport);

    ldapServer.start();

    port = getTcpTransportPort();

    checkLdapEntries();
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

  private void checkLdapEntries() {
    lookup(LdapTestConstants.O_SEVEN_SEAS);
    lookup(LdapTestConstants.OU_PEOPLE);
    lookup(LdapTestConstants.CN_FOO);
  }

  /**
   * Stops the test AD.
   */
  @Deactivate
  public void deactivate() throws Exception {
    ldapServer.stop();
    directoryService.shutdown();
    logService.log(LogService.LOG_WARNING,
        "Waiting 35 seconds for the UnorderedThreadPoolExecutor to shutdown"
            + " gracefully, it was instantiated in the LdapServer.start() method"
            + " with default keep alive 30 seconds.");
    Thread.sleep(SLEEP_TIME);
  }

  @Override
  public int getPort() {
    return port;
  }

  private int getTcpTransportPort() {
    Transport[] transports = ldapServer.getTransports();
    for (Transport transport : transports) {
      if (transport instanceof TcpTransport) {
        TcpTransport tcpTransport = (TcpTransport) transport;
        SocketAcceptor socketAcceptor = tcpTransport.getAcceptor();
        InetSocketAddress localAddress = socketAcceptor.getLocalAddress();
        int port = localAddress.getPort();
        return port;
      }
    }
    throw new IllegalStateException("Ldap port is not defined!");
  }

  private void initFoo(final DnFactory dnFactory) throws LdapInvalidDnException, LdapException {
    Dn fooDn = dnFactory.create(LdapTestConstants.CN_FOO);
    if (!directoryService.getAdminSession().exists(fooDn)) {
      Entry fooEntry = directoryService.newEntry(fooDn);
      fooEntry.add(SchemaConstants.OBJECT_CLASS_AT,
          SchemaConstants.TOP_OC, SchemaConstants.PERSON_OC,
          SchemaConstants.ORGANIZATIONAL_PERSON_OC,
          SchemaConstants.INET_ORG_PERSON_OC);
      fooEntry.add(SchemaConstants.CN_AT, "foo");
      fooEntry.add(SchemaConstants.SN_AT, "Foo");
      fooEntry.add("mail", LdapTestConstants.FOO_MAIL);
      fooEntry.add(SchemaConstants.USER_PASSWORD_AT, LdapTestConstants.FOO_CREDENTIAL);
      directoryService.getAdminSession().add(fooEntry);
    }
  }

  private void initPeople(final DnFactory dnFactory) throws LdapInvalidDnException, LdapException {
    Dn peopleDn = dnFactory.create(LdapTestConstants.OU_PEOPLE);
    if (!directoryService.getAdminSession().exists(peopleDn)) {
      Entry peopleEntry = directoryService.newEntry(peopleDn);
      peopleEntry.add(SchemaConstants.OBJECT_CLASS_AT,
          SchemaConstants.TOP_OC, SchemaConstants.ORGANIZATIONAL_UNIT_OC);
      peopleEntry.add(SchemaConstants.OU_AT,
          "people");
      directoryService.getAdminSession().add(peopleEntry);
    }
  }

  private void initSevenSeas(final SchemaManager schemaManager, final DnFactory dnFactory)
      throws LdapInvalidDnException, Exception, LdapException {
    Dn sevenSeasDn = dnFactory.create(LdapTestConstants.O_SEVEN_SEAS);
    JdbmPartition sevenSeasPartition = addPartition(schemaManager, dnFactory, "sevenSeas",
        sevenSeasDn);
    addIndex(sevenSeasPartition, "mail");
    if (!directoryService.getAdminSession().exists(sevenSeasDn)) {
      Entry sevenSeasEntry = directoryService.newEntry(sevenSeasDn);
      sevenSeasEntry.add(SchemaConstants.OBJECT_CLASS_AT,
          SchemaConstants.TOP_OC, SchemaConstants.ORGANIZATION_OC);
      sevenSeasEntry.add(SchemaConstants.O_AT,
          "sevenSeas");
      directoryService.getAdminSession().add(sevenSeasEntry);
    }
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

  public void setLogService(final LogService logService) {
    this.logService = logService;
  }

}
