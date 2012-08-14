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

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * PicketBox Keystore {@link Provider}
 *
 * @author anil saldhana
 * @since Aug 13, 2012
 */
public class PicketBoxKeyStoreDBProvider extends Provider {
    private static final long serialVersionUID = 1L;

    private HashSet<Service> services = new HashSet<Provider.Service>();

    public PicketBoxKeyStoreDBProvider(String name, double version, String info) {
        super(name, version, info);
        services.add(new PicketBoxKeyStoreService(this, "jks", "algo", PicketBoxKeyStoreService.class.getName(), null, null));
    }

    @Override
    public synchronized Service getService(String type, String algorithm) {
        if ("KeyStore".equals(type) && "jks".equals(algorithm)) {
            return services.iterator().next();
        }
        if ("jks".equals(type) && "algo".equals(algorithm)) {
            return services.iterator().next();
        }
        throw new RuntimeException();
    }

    @Override
    public synchronized Set<Service> getServices() {
        return services;
    }

    @Override
    public Object get(Object key) {
        throw new RuntimeException();
    }

    public class PicketBoxKeyStoreService extends Service {
        public PicketBoxKeyStoreService(Provider provider, String type, String algorithm, String className,
                List<String> aliases, Map<String, String> attributes) {
            super(provider, type, algorithm, className, aliases, attributes);
        }

        @Override
        public Object newInstance(Object constructorParameter) throws NoSuchAlgorithmException {
            PicketBoxDBKeyStore ks = new PicketBoxDBKeyStore();
            // return services.iterator().next();
            return ks;
        }

        @Override
        public boolean supportsParameter(Object parameter) {
            throw new RuntimeException();
        }
    }
}