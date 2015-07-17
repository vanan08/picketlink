/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.picketlink.identity.federation.core.wstrust;

/**
 * Simple factory for creating {@link STSClient}s
 *
 * @author <a href="mailto:dbevenius@jboss.com">Daniel Bevenius</a>
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 *
 */
public final class STSClientFactory {

    private static STSClientPool stsClientPool;

    private static final STSClientPool simpleClientPoolFactory = new STSClientPool() {

        @Override
        public void createPool(STSClientConfig config) {
        }

        @Override
        public void createPool(int initialNumberOfClients, STSClientConfig config) {
        }

        @Override
        public void createPool(int initialNumberOfClients, STSClientCreationCallBack callBack) {
        }

        @Override
        public void destroyPool(STSClientConfig config) {
        }

        @Override
        public void destroyPool(String moduleName) {
        }

        @Override
        public void returnClient(STSClient stsClient) {
        }

        @Override
        public STSClient getClient(STSClientConfig config) {
            return new STSClient(config);
        }

        @Override
        public boolean configExists(STSClientConfig config) {
            return true;
        }

    };


    public static STSClientPool getInstance() {
        if (stsClientPool == null) {
            // when stsClientPool is not initialized, just use this simple pool factory which just returns new STSClient
            // each time getClient method is called
            return simpleClientPoolFactory;
        }
        return stsClientPool;
    }


    public static void setInstance(STSClientPool clientPool) {
        if (stsClientPool == null) {
            stsClientPool = clientPool;
        }
    }

    /**
     * This method creates STS client directly without pooling based on STSClient config.
     *
     * Recommended method to use instead is getClient(final STSClientConfig config).
     *
     * @param config
     * @return STSClient
     */
    public STSClient create(final STSClientConfig config) {
        return new STSClient(config);
    }

}
