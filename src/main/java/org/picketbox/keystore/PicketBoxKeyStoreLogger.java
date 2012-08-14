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

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Cause;
import org.jboss.logging.LogMessage;
import org.jboss.logging.Logger;
import org.jboss.logging.Message;
import org.jboss.logging.MessageLogger;

/**
 * An subclass of {@link BasicLogger} from JBoss Logging
 *
 * @author Stefan Guilhen
 * @since Jul 10, 2012
 */
@MessageLogger(projectCode = "PBOXCORE")
public interface PicketBoxKeyStoreLogger extends BasicLogger {

    PicketBoxKeyStoreLogger LOGGER = Logger.getMessageLogger(PicketBoxKeyStoreLogger.class, PicketBoxKeyStoreLogger.class
            .getPackage().getName());

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 500, value = "Executing query: '%s' with parameters: %s")
    void debugQueryExecution(String query, String params);

    @LogMessage(level = Logger.Level.INFO)
    @Message(id = 501, value = "Starting PicketBox")
    void startingPicketBox();

    @LogMessage(level = Logger.Level.TRACE)
    @Message(id = 502, value = "Checking search result %s")
    void traceCheckSearchResult(String searchResult);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 503, value = "Failed to parse %s as number, using default value %s")
    void debugFailureToParseNumberProperty(String property, long defaultValue);

    @LogMessage(level = Logger.Level.TRACE)
    @Message(id = 504, value = "Searching rolesCtxDN %s with roleFilter: %s, filterArgs: %s, roleAttr: %s, searchScope: %s, searchTimeLimit: %s")
    void traceRolesDNSearch(String dn, String roleFilter, String filterArgs, String roleAttr, int searchScope,
            int searchTimeLimit);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 505, value = "Failed to query %s from %s")
    void debugFailureToQueryLDAPAttribute(String attributeName, String contextName, @Cause Throwable throwable);

    @LogMessage(level = Logger.Level.TRACE)
    @Message(id = 506, value = "Following roleDN %s")
    void traceFollowRoleDN(String roleDN);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 507, value = "No attribute %s found in search result %s")
    void debugFailureToFindAttrInSearchResult(String attrName, String searchResult);

    @LogMessage(level = Logger.Level.DEBUG)
    @Message(id = 508, value = "Failed to locate roles")
    void debugFailureToExecuteRolesDNSearch(@Cause Throwable throwable);

    @LogMessage(level = Logger.Level.WARN)
    @Message(id = 509, value = "ALL RESOURCES WILL BE PROTECTED. MAYBE YOU DID NOT DEFINE WHICH RESOURCES SHOULD BE PROTECTED.")
    void allResourcesWillBeProteced();

}