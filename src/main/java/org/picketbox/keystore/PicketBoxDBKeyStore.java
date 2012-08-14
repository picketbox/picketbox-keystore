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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Date;
import java.util.Enumeration;

import org.picketbox.keystore.util.Base64;
import org.picketbox.keystore.util.KeyStoreDBUtil;

/**
 * An extension of {@link KeyStoreSpi}
 *
 * @author anil saldhana
 * @since Aug 13, 2012
 */
public class PicketBoxDBKeyStore extends KeyStoreSpi {
    String type = "jks";

    private Connection con = null;

    private String storeTableName = null;

    @Override
    public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
        try {
            String selectSQL = "SELECT KEY FROM " + storeTableName + " WHERE ID = ?";
            PreparedStatement preparedStatement = con.prepareStatement(selectSQL);
            preparedStatement.setString(1, alias);
            ResultSet rs = preparedStatement.executeQuery();
            while (rs.next()) {
                String certString = rs.getString("KEY");
                byte[] keyBytes = Base64.decode(certString);
                ObjectInputStream oos = new ObjectInputStream(new ByteArrayInputStream(keyBytes));
                return (Key) oos.readObject();
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return null;
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
        try {
            String selectSQL = "SELECT CHAIN FROM " + storeTableName + " WHERE ID = ?";
            PreparedStatement preparedStatement = con.prepareStatement(selectSQL);
            preparedStatement.setString(1, alias);
            ResultSet rs = preparedStatement.executeQuery();
            while (rs.next()) {
                String certString = rs.getString("CHAIN");
                byte[] cert = Base64.decode(certString);
                ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(cert));
                return (Certificate[]) ois.readObject();
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return null;
    }

    @Override
    public Certificate engineGetCertificate(String alias) {
        try {
            String selectSQL = "SELECT CERT FROM " + storeTableName + " WHERE ID = ?";
            PreparedStatement preparedStatement = con.prepareStatement(selectSQL);
            preparedStatement.setString(1, alias);
            ResultSet rs = preparedStatement.executeQuery();
            while (rs.next()) {
                String certString = rs.getString("CERT");
                byte[] cert = Base64.decode(certString);
                CertificateFactory fact = CertificateFactory.getInstance("x509");
                return fact.generateCertificate(new ByteArrayInputStream(cert));
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return null;
    }

    @Override
    public Date engineGetCreationDate(String alias) {
        try {
            String selectSQL = "SELECT CREATED FROM " + storeTableName + " WHERE ID = ?";
            PreparedStatement preparedStatement = con.prepareStatement(selectSQL);
            preparedStatement.setString(1, alias);
            ResultSet rs = preparedStatement.executeQuery();
            while (rs.next()) {
                String dateString = rs.getString("CREATED");
                long timeValue = Long.parseLong(dateString);
                return new Date(timeValue);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return null;
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException {
        engineSetKeyEntry(alias, key.getEncoded(), chain);
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
        PreparedStatement preparedStatement = null;
        try {
            String encodedKey = Base64.encodeBytes(key);

            String insertTableSQL = "INSERT INTO " + storeTableName + "(ID,KEY,CREATED) VALUES" + "(?,?,?)";
            boolean rowExists = checkRowExists(alias);

            String thirdIndex = (new Date()).getTime() + "";

            if (rowExists) {
                insertTableSQL = "UPDATE " + storeTableName + " SET ID= ? , KEY = ?  WHERE ID = ?";
                thirdIndex = alias;
            }

            preparedStatement = con.prepareStatement(insertTableSQL);
            preparedStatement.setString(1, alias);
            preparedStatement.setString(2, encodedKey);
            preparedStatement.setString(3, thirdIndex);
            preparedStatement.executeUpdate();

            preparedStatement.close();
            storeCertificateChain(alias, chain);
        } catch (Exception e) {
            throw new KeyStoreException(e);
        } finally {
            if (preparedStatement != null) {
                safeClose(preparedStatement);
            }
        }
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
        PreparedStatement preparedStatement = null;
        try {
            String encodedCert = Base64.encodeBytes(cert.getEncoded());

            String insertTableSQL = "INSERT INTO " + storeTableName + "(ID,CERT,CREATED) VALUES" + "(?,?,?)";

            String thirdIndex = (new Date()).getTime() + "";

            boolean rowExists = checkRowExists(alias);
            if (rowExists) {
                insertTableSQL = "UPDATE " + storeTableName + " SET ID= ? , CERT = ?  WHERE ID = ?";
                thirdIndex = alias;
            }
            preparedStatement = con.prepareStatement(insertTableSQL);
            preparedStatement.setString(1, alias);
            preparedStatement.setString(2, encodedCert);
            preparedStatement.setString(3, thirdIndex);
            preparedStatement.executeUpdate();

            preparedStatement.close();
        } catch (Exception e) {
            throw new KeyStoreException(e);
        } finally {
            if (preparedStatement != null) {
                safeClose(preparedStatement);
            }

        }
    }

    @Override
    public void engineDeleteEntry(String alias) throws KeyStoreException {
        throw new RuntimeException();
    }

    @Override
    public Enumeration<String> engineAliases() {
        throw new RuntimeException();
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        throw new RuntimeException();
    }

    @Override
    public int engineSize() {
        throw new RuntimeException();
    }

    @Override
    public boolean engineIsKeyEntry(String alias) {
        try {
            String selectSQL = "SELECT KEY FROM " + storeTableName + " WHERE ID = ?";
            PreparedStatement preparedStatement = con.prepareStatement(selectSQL);
            preparedStatement.setString(1, alias);
            ResultSet rs = preparedStatement.executeQuery();
            while (rs.next()) {
                return true; // Atleast one entry
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return false;
    }

    @Override
    public boolean engineIsCertificateEntry(String alias) {
        try {
            String selectSQL = "SELECT CERT FROM " + storeTableName + " WHERE ID = ?";
            PreparedStatement preparedStatement = con.prepareStatement(selectSQL);
            preparedStatement.setString(1, alias);
            ResultSet rs = preparedStatement.executeQuery();
            while (rs.next()) {
                return true; // Atleast one entry
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return false;
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert) {
        throw new RuntimeException();
    }

    @Override
    public void engineStore(OutputStream stream, char[] password) throws IOException, NoSuchAlgorithmException,
            CertificateException {
        // We do not do anything
    }

    @Override
    public void engineLoad(InputStream stream, char[] password) throws IOException, NoSuchAlgorithmException,
            CertificateException {
        if (con == null) {
            loadDatabase();
        }
    }

    private void loadDatabase() {
        KeyStoreDBUtil util = new KeyStoreDBUtil();
        con = util.getConnection();
        storeTableName = util.getStoreTableName();
    }

    private void safeClose(Statement stmt) {
        if (stmt != null) {
            try {
                stmt.close();
            } catch (SQLException ignore) {
            }
        }
    }

    private void storeCertificateChain(String alias, Certificate[] chain) throws KeyStoreException {
        PreparedStatement preparedStatement = null;
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(chain);

            String encodedChain = Base64.encodeBytes(baos.toByteArray());

            String insertTableSQL = "INSERT INTO " + storeTableName + "(ID,CHAIN,CREATED) VALUES" + "(?,?,?)";

            String thirdIndex = (new Date()).getTime() + "";

            boolean rowExists = checkRowExists(alias);

            if (rowExists) {
                insertTableSQL = "UPDATE " + storeTableName + " SET ID= ? , CHAIN = ?  WHERE ID = ?";
                thirdIndex = alias;
            }
            preparedStatement = con.prepareStatement(insertTableSQL);
            preparedStatement.setString(1, alias);
            preparedStatement.setString(2, encodedChain);
            preparedStatement.setString(3, thirdIndex);
            preparedStatement.executeUpdate();

            preparedStatement.close();
        } catch (Exception e) {
            throw new KeyStoreException(e);
        } finally {
            if (preparedStatement != null) {
                safeClose(preparedStatement);
            }
        }
    }

    private boolean checkRowExists(String alias) throws Exception {
        try {
            String selectSQL = "SELECT ID FROM " + storeTableName + " WHERE ID = ?";
            PreparedStatement preparedStatement = con.prepareStatement(selectSQL);
            preparedStatement.setString(1, alias);
            ResultSet rs = preparedStatement.executeQuery();
            while (rs.next()) {
                return true; // Atleast one entry
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return false;
    }
}