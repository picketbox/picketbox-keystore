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
package org.picketbox.test.keystore;

import static org.junit.Assert.assertNotNull;

import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.cert.Certificate;

import org.junit.Test;
import org.picketbox.keystore.util.CertificateUtil;

/**
 * Unit test the {@link CertificateUtil}
 *
 * @author anil saldhana
 * @since Aug 16, 2012
 */
public class CertificateUtilTestCase {

    /**
     * Create a Self Signed Certificate
     * @throws Exception
     */
    @Test
    public void testCertificateGeneration() throws Exception {
        CertificateUtil util = new CertificateUtil();

        KeyPair pair = util.generateKeyPair("RSA");

        String DN = "cn=jbid";
        int numberOfDays = 365;
        Certificate cert = util.createX509V1Certificate(pair, numberOfDays, DN);
        assertNotNull(cert);
    }

    /**
     * Create a PKCS#10 CSR
     * @throws Exception
     */
    @Test
    public void testCSR() throws Exception {

        CertificateUtil util = new CertificateUtil();

        KeyPair pair = util.generateKeyPair("RSA");

        String DN = "cn=jbid";

        byte[] csr = util.createCSR(DN, pair);
        String pem = util.getPEM(csr);
        FileOutputStream os = new FileOutputStream("target/test.csr");
        os.write(pem.getBytes());
        os.close();
    }
}