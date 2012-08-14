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
package org.picketbox.keystore.util;

import java.io.InputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.util.Properties;

/**
 * Util class to deal with a database
 *
 * @author anil saldhana
 * @since Aug 13, 2012
 */
public class KeyStoreDBUtil {

    private Connection con = null;

    private String storeTableName;

    public KeyStoreDBUtil() {
        try {
            InputStream is = getClass().getClassLoader().getResourceAsStream("picketbox-keystore-db.properties");
            // We just load a custom properties or xml file
            Properties properties = new Properties();
            properties.load(is);

            // Load the Driver class.
            Class.forName(properties.getProperty("connection.class"));
            // If you are using any other database then load the right driver here.

            // Create the connection using the static getConnection method
            con = DriverManager.getConnection(properties.getProperty("connection.url"),
                    properties.getProperty("connection.username"), properties.getProperty("connection.password"));

            storeTableName = properties.getProperty("store.table");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Get the {@link Connection}
     *
     * @return
     */
    public Connection getConnection() {
        return con;
    }

    public String getStoreTableName() {
        return storeTableName;
    }
}