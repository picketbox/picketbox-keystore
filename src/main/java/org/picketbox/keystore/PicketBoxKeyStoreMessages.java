/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2012, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.picketbox.keystore;

import java.io.IOException;

import org.jboss.logging.Cause;
import org.jboss.logging.Message;
import org.jboss.logging.MessageBundle;
import org.jboss.logging.Messages;

/**
 * An instance of {@link MessageBundle} from JBoss Logging
 *
 * @author Stefan Guilhen
 * @since Jul 10, 2012
 */
@MessageBundle(projectCode = "PBOXKS")
public interface PicketBoxKeyStoreMessages {

    PicketBoxKeyStoreMessages MESSAGES = Messages.getBundle(PicketBoxKeyStoreMessages.class);

    @Message(id = 7, value = "The argument %s cannot be null")
    IllegalArgumentException invalidNullArgument(String argName);

    @Message(id = 8, value = "Error encoding from file %s")
    IllegalStateException errorEncodingFromFile(String fileName, @Cause Throwable throwable);

    @Message(id = 9, value = "Error decoding from file %s")
    IllegalStateException errorDecodingFromFile(String fileName, @Cause Throwable throwable);

    @Message(id = 10, value = "Error decoding from file %s: file is too big (%s bytes)")
    IllegalStateException errorDecodingFromBigInputFile(String fileName, long fileSize);

    @Message(id = 11, value = "Base64 input not properly padded")
    IOException invalidBase64Padding();

    @Message(id = 12, value = "Invalid Base64 character found: %s")
    String invalidBase64CharacterMessage(byte character);

    @Message(id = 13, value = "Error reading Base64 stream: nothing to read")
    IOException errorReadingBase64Stream();

    @Message(id = 14, value = "Unable to find properties file: %s")
    RuntimeException unableToFindPropertiesFile(String fileName);

    @Message(id = 17, value = "Missing required property: %s")
    IllegalStateException missingRequiredProperty(String property);

    @Message(id = 18, value = "Invalid configuration: either provide a JPA config name or a DataSource (via injection or JNDI)")
    IllegalStateException invalidDatabaseAuthenticationManagerConfiguration();

    @Message(id = 19, value = "Query %s found no results")
    String queryFoundNoResultsMessage(String query);

    @Message(id = 22, value = "Instance already started.")
    IllegalStateException instanceAlreadyStarted();

    @Message(id = 23, value = "Instance alredy stopped.")
    IllegalStateException instanceAlreadyStopped();

    @Message(id = 24, value = "Instance not started.")
    IllegalStateException instanceNotStarted();

    @Message(id = 29, value = "User session is not valid.")
    IllegalStateException invalidUserSession();

    @Message(id = 30, value = "Failed to close NamingEnumeration")
    RuntimeException namingEnumerationClose(@Cause Throwable throwable);

    @Message(id = 31, value = "Failed to construct Ldap Context")
    RuntimeException ldapCtxConstructionFailure(@Cause Throwable throwable);

    @Message(id = 32, value = "Ldap Search Config is missing")
    RuntimeException ldapSearchConfigMissing();

    @Message(id = 33, value = "Ldap Search Base is missing")
    RuntimeException ldapSearchBaseMissing();

    @Message(id = 34, value = "Ldap Store Config is missing")
    RuntimeException ldapStoreConfigMissing();

    @Message(id = 35, value = "User Dn String is missing")
    RuntimeException userDNStringMissing();

    @Message(id = 36, value = "LDAP Search Failed.")
    RuntimeException ldapSearchFailed(@Cause Throwable t);

    @Message(id = 37, value = "Basic LDAP Config Missing.")
    RuntimeException basicLdapConfigMissing();

    @Message(id = 45, value = "Unsupported Feature.")
    IllegalStateException unsupportedFeature();

    @Message(id = 46, value = "Unable to instantiate: %s")
    IllegalStateException unableToInstantiate(String fqn);
}