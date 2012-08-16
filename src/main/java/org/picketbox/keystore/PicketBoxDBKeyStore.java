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

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.URL;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Date;
import java.util.Enumeration;
import java.util.Scanner;
import java.util.Vector;

import org.picketbox.keystore.util.Base64;
import org.picketbox.keystore.util.CertificateUtil;
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

    private String storeTableName = null, metadataTableName = null;

    @Override
    public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {

        try {
            if (matchKeyPass(alias, password) == false) {
                throw new UnrecoverableKeyException("Key Password does not match");
            }
            String selectSQL = "SELECT KEY FROM " + storeTableName + " WHERE ID = ?";
            PreparedStatement preparedStatement = con.prepareStatement(selectSQL);
            preparedStatement.setString(1, alias);
            ResultSet rs = preparedStatement.executeQuery();
            while (rs.next()) {
                String keyString = rs.getString("KEY");
                byte[] keyBytes = Base64.decode(keyString);
                ObjectInputStream oos = new ObjectInputStream(new ByteArrayInputStream(keyBytes));
                return (Key) oos.readObject();
            }
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        } catch (SQLException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (ClassNotFoundException e) {
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
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(key);

            engineSetKeyEntry(alias, baos.toByteArray(), chain);
            storeKeyPass(alias, password);
        } catch (IOException e) {
            throw new KeyStoreException(e);
        }
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
            if (chain != null) {
                storeCertificateChain(alias, chain);
            }
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
        try {
            if (!checkRowExists(alias))
                return;
        } catch (Exception e1) {
            throw new RuntimeException(e1);
        }
        String insertTableSQL = "UPDATE " + storeTableName + " SET ID= ? , KEY = ?  WHERE ID = ?";
        PreparedStatement preparedStatement = null;
        try {
            preparedStatement = con.prepareStatement(insertTableSQL);
            preparedStatement.setString(1, alias);
            preparedStatement.setString(2, "");
            preparedStatement.setString(3, alias);
            preparedStatement.executeUpdate();

            preparedStatement.close();
        } catch (Exception e) {
            throw new KeyStoreException(e);
        } finally {
            if (preparedStatement != null) {
                safeClose(preparedStatement);
            }
        }
        throw new RuntimeException();
    }

    @Override
    public Enumeration<String> engineAliases() {
        Vector<String> vect = new Vector<String>();
        try {
            String selectSQL = "SELECT ID FROM " + storeTableName;
            Statement stat = con.createStatement();
            ResultSet rs = stat.executeQuery(selectSQL);
            while (rs.next()) {
                vect.add(rs.getString(1));
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return vect.elements();
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        try {
            return checkRowExists(alias);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public int engineSize() {
        try {
            String selectSQL = "SELECT COUNT(*) FROM " + storeTableName;
            Statement stat = con.createStatement();
            ResultSet rs = stat.executeQuery(selectSQL);
            while (rs.next()) {
                return rs.getInt(1);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return 0;
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
        try {
            String selectSQL = "SELECT ID FROM " + storeTableName + " WHERE CERT = ?";
            PreparedStatement preparedStatement = con.prepareStatement(selectSQL);
            String encoded = Base64.encodeBytes(cert.getEncoded());

            preparedStatement.setString(1, encoded);
            ResultSet rs = preparedStatement.executeQuery();
            while (rs.next()) {
                return rs.getString("ID");
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return null;
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
            loadDatabase(password);
        }
    }

    /**
     * Check if the salt exists
     *
     * @return
     */
    public boolean existsSalt() {
        return getSalt() != null;
    }

    /**
     * Check if the master password exists
     *
     * @return
     */
    public boolean existsMasterPassword() {
        return getMasterPassword() != null;
    }

    /**
     * Store Master Password if not already present
     *
     * @param masterPassword
     */
    public void storeMasterPassword(char[] masterPassword) {
        if (getMasterPassword() != null) {
            throw new RuntimeException("Master Password already present");
        }

        String salt = getSalt();
        PreparedStatement preparedStatement = null;
        try {

            String encodedPass = KeyStoreDBUtil.saltedHmacMD5(salt, (new String(masterPassword).getBytes()));

            String insertTableSQL = "UPDATE " + metadataTableName + " SET PASS = ?";

            preparedStatement = con.prepareStatement(insertTableSQL);
            preparedStatement.setString(1, encodedPass);
            preparedStatement.executeUpdate();

            preparedStatement.close();
        } catch (Exception e) {
            throw new RuntimeException(e);
        } finally {
            if (preparedStatement != null) {
                safeClose(preparedStatement);
            }
        }
    }

    private void loadDatabase(char[] password) {
        if (password == null) {
            throw new IllegalArgumentException("KeyStore Password is null");
        }
        loadDBConnection();
        // Let us evaluate the password
        String salt = getSalt();
        if (salt == null)
            throw new RuntimeException("Salt is null");

        try {
            String saltedPassword = KeyStoreDBUtil.saltedHmacMD5(salt, (new String(password)).getBytes());
            if (saltedPassword.equals(getMasterPassword()) == false) {
                throw new RuntimeException("The master password does not match");
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    private void loadDBConnection() {
        KeyStoreDBUtil util = new KeyStoreDBUtil();
        con = util.getConnection();
        storeTableName = util.getStoreTableName();
        metadataTableName = util.getMetadataTableName();
    }

    private void safeClose(Statement stmt) {
        if (stmt != null) {
            try {
                stmt.close();
            } catch (SQLException ignore) {
            }
        }
    }

    private String getSalt() {
        try {
            String selectSQL = "SELECT SALT FROM " + metadataTableName;
            Statement statement = con.createStatement();
            ResultSet rs = statement.executeQuery(selectSQL);
            while (rs.next()) {
                return rs.getString("SALT");
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return null;
    }

    private String getMasterPassword() {
        try {
            String selectSQL = "SELECT PASS FROM " + metadataTableName;
            Statement statement = con.createStatement();
            ResultSet rs = statement.executeQuery(selectSQL);
            while (rs.next()) {
                return rs.getString("PASS");
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return null;
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

    private boolean matchKeyPass(String alias, char[] keypass) throws KeyStoreException {
        try {
            String salt = getSalt();
            String selectSQL = "SELECT KEYPASS FROM " + storeTableName + " WHERE ID =?";
            PreparedStatement preparedStatement = con.prepareStatement(selectSQL);
            preparedStatement.setString(1, alias);
            ResultSet rs = preparedStatement.executeQuery();
            while (rs.next()) {
                String storedPass = rs.getString("KEYPASS");
                if (storedPass == null)
                    return false;
                return storedPass.equals(KeyStoreDBUtil.saltedHmacMD5(salt, (new String(keypass)).getBytes())); // Atleast one
                // entry
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return false;
    }

    private void storeKeyPass(String alias, char[] keypass) throws KeyStoreException {
        PreparedStatement preparedStatement = null;
        try {
            String salt = getSalt();

            String encodedPass = KeyStoreDBUtil.saltedHmacMD5(salt, (new String(keypass).getBytes()));

            String insertTableSQL = "UPDATE " + storeTableName + " SET KEYPASS = ? WHERE ID=?";

            preparedStatement = con.prepareStatement(insertTableSQL);
            preparedStatement.setString(1, encodedPass);
            preparedStatement.setString(2, alias);
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

    public static void main(String[] args) throws Exception {
        PicketBoxDBKeyStore ks = new PicketBoxDBKeyStore();
        ks.loadDBConnection();

        Scanner scanner = new Scanner(System.in);
        while (true) {
            String cmd = "Enter 1: Import KeyPair " + "2: Create a KeyPair and Certificate " + "3: Create CSR "
                    + "4: Check Master Password Exists " + "5: Check Master Salt Exists";

            System.out.println(cmd);
            int choice = scanner.nextInt();
            switch (choice) {
                case 1:
                    String keystoreurl = "";
                    do {
                        System.out.println("Enter Keystore URL=");
                        keystoreurl = readLine();
                    } while (keystoreurl.isEmpty());

                    String keystorePass = "";
                    do {
                        System.out.println("Enter KeyStore Password=");
                        keystorePass = readPassword();
                    } while (keystorePass.isEmpty());

                    KeyStore keystore = null;
                    // Load Keystore
                    InputStream is = PicketBoxDBKeyStore.class.getClassLoader().getResourceAsStream(keystoreurl);
                    if (is == null) {
                        // try URL
                        try {
                            URL keyurl = new URL(keystoreurl);
                            is = keyurl.openStream();
                        } catch (Exception e) {
                            // Unable to get to the keystore
                            throw new RuntimeException("Unable to load keystore:" + keystoreurl);
                        }
                    }
                    if (is != null) {
                        keystore = KeyStore.getInstance(KeyStore.getDefaultType());
                        keystore.load(is, keystorePass.toCharArray());
                        System.out.println("Java JKS KeyStore loaded from " + keystoreurl);
                    }

                    String alias = "";
                    do {
                        System.out.println("Enter alias=");
                        alias = readLine();
                    } while (alias.isEmpty());

                    String keyPass = "";
                    do {
                        System.out.println("Enter Key Password=");
                        keyPass = readPassword();
                    } while (keyPass.isEmpty());

                    if (keystore != null) {
                        KeyHolder holder = getPrivateKey(keystore, alias, keyPass.toCharArray());
                        System.out.println("Retrieved Private Key and Certificate from JKS Keystore:" + keystoreurl);
                        ks.engineSetKeyEntry(alias, holder.privateKey, keyPass.toCharArray(), null);
                        ks.engineSetCertificateEntry(alias, holder.cert);
                    }

                    break;
                case 2:
                    generateCertificate(ks);
                    break;
                case 3:
                    alias = "";
                    do {
                        System.out.println("Enter alias=");
                        alias = readLine();
                    } while (alias.isEmpty());
                    keyPass = "";
                    do {
                        System.out.println("Enter Key Password=");
                        keyPass = readPassword();
                    } while (keyPass.isEmpty());
                    String csrFile = "";
                    do {
                        System.out.println("Enter filename to store CSR=");
                        csrFile = readLine();
                    } while (csrFile.isEmpty());
                    FileOutputStream fos = new FileOutputStream(csrFile);

                    generateCSR(ks, alias, keyPass.toCharArray(), fos);
                    fos.close();

                    break;
                case 4:
                    System.out.println(ks.existsMasterPassword());
                    break;
                case 5:
                    System.out.println(ks.existsSalt());
                    break;
                default:
                    System.exit(0);
                    break;
            }
        }

    }

    private static void generateCertificate(PicketBoxDBKeyStore ks) throws Exception {
        CertificateUtil util = new CertificateUtil();
        String alias = "";
        do {
            System.out.println("Enter alias=");
            alias = readLine();
        } while (alias.isEmpty());

        String dn = "";
        do {
            System.out.println("Enter Subject DN=");
            dn = readLine();
        } while (dn.isEmpty());

        String no = "";
        do {
            System.out.println("Enter Number Of Days Of Validity=");
            no = readLine();
        } while (no.isEmpty());

        int numberOfDays = Integer.parseInt(no);

        String keyPass = "";
        do {
            System.out.println("Enter Key Password=");
            keyPass = readPassword();
        } while (keyPass.isEmpty());

        KeyPair pair = util.generateKeyPair("RSA");
        Certificate cert = util.createX509V1Certificate(pair, numberOfDays, dn);

        if (ks != null) {
            ks.engineSetKeyEntry(alias, pair.getPrivate(), keyPass.toCharArray(), null);
            ks.engineSetCertificateEntry(alias, cert);
        }
    }

    private static void generateCSR(PicketBoxDBKeyStore ks, String alias, char[] keyPass, FileOutputStream fos)
            throws Exception {
        CertificateUtil util = new CertificateUtil();
        Certificate cert = ks.engineGetCertificate(alias);
        PrivateKey privateKey = (PrivateKey) ks.engineGetKey(alias, keyPass);
        KeyPair keyPair = new KeyPair(cert.getPublicKey(), privateKey);
        X509Certificate x509 = (X509Certificate) cert;
        byte[] csr = util.createCSR(x509.getSubjectDN().getName(), keyPair);
        String pem = util.getPEM(csr);
        fos.write(pem.getBytes());
    }

    private static KeyHolder getPrivateKey(KeyStore keystore, String alias, char[] password) {
        KeyHolder holder = new KeyHolder();
        try {
            // Get private key
            Key key = keystore.getKey(alias, password);
            if (key instanceof PrivateKey) {
                holder.privateKey = key;
                // Get certificate of public key
                holder.cert = keystore.getCertificate(alias);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return holder;
    }

    private static class KeyHolder {
        private Key privateKey;
        private Certificate cert;
    }

    private static String readLine() throws IOException {
        if (System.console() != null) {
            return System.console().readLine();
        }
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        return reader.readLine();
    }

    private static String readPassword() throws IOException {
        if (System.console() != null)
            return new String(System.console().readPassword());
        return readLine();
    }
}