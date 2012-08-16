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

import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;

/**
 * Utility class using BouncyCastle to deal with {@link Certificate} operations
 *
 * @author anil saldhana
 * @since Aug 16, 2012
 */
public class CertificateUtil {

    private static SecureRandom random = new SecureRandom();

    static {
        SecurityActions.addProvider(new BouncyCastleProvider());
    };

    /**
     * Create a X509 V1 {@link Certificate}
     *
     * @param pair {@link KeyPair}
     * @param numberOfDays Number of days the certificate will be valid
     * @param DN The DN of the subject
     * @return
     * @throws CertificateException
     */
    public Certificate createX509V1Certificate(KeyPair pair, int numberOfDays, String DN) throws CertificateException {
        try {
            AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1withRSA");
            AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

            AsymmetricKeyParameter privateKeyAsymKeyParam = PrivateKeyFactory.createKey(pair.getPrivate().getEncoded());
            SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded());

            ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(privateKeyAsymKeyParam);

            Date startDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
            Date endDate = new Date(System.currentTimeMillis() + numberOfDays * 24 * 60 * 60 * 1000);

            X500Name name = new X500Name(DN);

            BigInteger serialNum = createSerialNumber();
            X509v1CertificateBuilder v1CertGen = new X509v1CertificateBuilder(name, serialNum, startDate, endDate, name,
                    subPubKeyInfo);

            X509CertificateHolder certificateHolder = v1CertGen.build(sigGen);
            return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateHolder);
        } catch (CertificateException e1) {
            throw e1;
        } catch (Exception e) {
            throw new CertificateException(e);
        }
    }

    /**
     * Create a certificate signing request
     *
     * @throws CertificateException
     */
    public byte[] createCSR(String dn, KeyPair keyPair) throws CertificateException {
        X500Name name = new X500Name(dn);
        try {

            AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1withRSA");
            AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

            AsymmetricKeyParameter privateKeyAsymKeyParam = PrivateKeyFactory.createKey(keyPair.getPrivate().getEncoded());

            ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(privateKeyAsymKeyParam);

            SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
            PKCS10CertificationRequestBuilder builder = new PKCS10CertificationRequestBuilder(name, subPubKeyInfo);
            PKCS10CertificationRequest csr = builder.build(sigGen);
            return csr.getEncoded();
        } catch (Exception e) {
            throw new CertificateException(e);
        }
    }

    /**
     * Get the CSR as a PEM formatted String
     *
     * @param csrEncoded
     * @return
     * @throws IOException
     */
    public String getPEM(byte[] csrEncoded) throws IOException {
        String type = "CERTIFICATE REQUEST";

        PemObject pemObject = new PemObject(type, csrEncoded);

        StringWriter str = new StringWriter();
        PEMWriter pemWriter = new PEMWriter(str);
        pemWriter.writeObject(pemObject);
        pemWriter.close();
        str.close();
        return str.toString();
    }

    /**
     * Generate a Key Pair
     *
     * @param algo (RSA, DSA etc)
     * @return
     * @throws GeneralSecurityException
     */
    public KeyPair generateKeyPair(String algo) throws GeneralSecurityException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algo);
        return kpg.genKeyPair();
    }

    /**
     * Create a random serial number
     *
     * @return
     * @throws GeneralSecurityException
     */
    public BigInteger createSerialNumber() throws GeneralSecurityException {
        BigInteger bi = new BigInteger(4, random);
        return bi;
    }
}