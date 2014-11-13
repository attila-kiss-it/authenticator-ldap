authenticator-ldap
==================

An OSGi component that can be used to authenticate users against an LDAP 
server. It is an implementation of the [authenticator-api][2] that can be used 
in concept [Everit Authentication][1].

#Component
The module contains one Declarative Services component. The component can be 
instantiated multiple times via Configuration Admin. The component registers 
the **org.everit.osgi.authenticator.Authenticator** OSGi service that 
implements the authentication against the configured LDAP server.

#Configuration
 - **Service Description**: The description of this component configuration. 
 It is used to easily identify the services registered by this component. 
 (service.description)
 - **LDAP URL**: The LDAP URL to connect to. (e.g. 
 ldap://<ldapDirectoryHostname>:<port>, ldap://localhost:10389) (url)
 - **System User DN**: The DN of the system user used to search for other 
 users. (e.g. uid=admin,ou=system) (systemUserDn)
 - **System User Password**: The password of the system user. 
 (systemUserPassword)
 - **User Base DN**: The base DN of the users to search for. (e.g. 
 ou=people,o=sevenSeas) (userBaseDn)
 - **User Serach Base**: The filter expression to use for the search. Must 
 contain exactly one substitution token '{0}' that will be replaced by the 
 users principal. (e.g. mail={0}) (userSearchBase)
 - **User DN Template**: The DN template used to create user DN if its 
 authentication succeeds. Must contain exactly one substitution token '{0}' 
 that will be replaced by the CN of the authenticated user. (e.g. 
 cn={0},ou=people,o=sevenSeas) (userDnTemplate)
 - **LogService OSGi filter**: OSGi Service filter expression for LogService 
 instance. (logService.target)

#Concept
Full authentication concept is available on blog post 
[Everit Authentication][1].

[1]: http://everitorg.wordpress.com/2014/07/31/everit-authentication/
[2]: https://github.com/everit-org/authenticator-api
