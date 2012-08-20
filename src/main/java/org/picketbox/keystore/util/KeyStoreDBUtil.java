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
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
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

    private String storeTableName, metadataTableName;

    private static final String PROPFILE = "picketbox-keystore-db.properties";

    public KeyStoreDBUtil() {
        try {
            InputStream is = getClass().getClassLoader().getResourceAsStream(PROPFILE);
            if (is == null)
                throw new IllegalStateException(PROPFILE + " not found");
            // We just load a custom properties or xml file
            Properties properties = new Properties();
            properties.load(is);

            // Load the Driver class.
            Class.forName(properties.getProperty("connection.class"));
            // If you are using any other database then load the right driver here.

            // Create the connection using the static getConnection method
            con = DriverManager.getConnection(properties.getProperty("connection.url"),
                    properties.getProperty("connection.username"), properties.getProperty("connection.password"));

            con.setAutoCommit(true);

            storeTableName = properties.getProperty("store.table");
            metadataTableName = properties.getProperty("metadata.table");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String saltedHmacMD5(String salt, byte[] data) throws InvalidKeyException, NoSuchAlgorithmException {
        // Create MessageDigest object for MD5
        MessageDigest digest = MessageDigest.getInstance("MD5");

        // Update input string in message digest
        digest.update(data, 0, data.length);

        // Converts message digest value in base 16 (hex)
        String md5 = new BigInteger(1, digest.digest()).toString(16);

        return md5 + salt;
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

    public String getMetadataTableName() {
        return metadataTableName;
    }
}