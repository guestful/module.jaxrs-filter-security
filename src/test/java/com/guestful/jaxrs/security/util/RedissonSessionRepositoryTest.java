/**
 * Copyright (C) 2013 Guestful (info@guestful.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.guestful.jaxrs.security.util;

import com.esotericsoftware.kryo.Kryo;
import com.guestful.jaxrs.security.session.StoredSession;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.redisson.Config;
import org.redisson.Redisson;
import org.redisson.codec.KryoCodec;
import org.redisson.core.RBucket;

import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertNotNull;

/**
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
@RunWith(JUnit4.class)
public final class RedissonSessionRepositoryTest {

    @Test
    public void test() throws Exception {
        KryoCodec.KryoPool kryoPool = new KryoCodec.KryoPoolImpl() {
            @Override
            protected Kryo createInstance() {
                Kryo kryo = new Kryo();
                return kryo;
            }
        };
        Config config = new Config();
        config.setCodec(new KryoCodec(kryoPool));

        // using local connection, it works:
        //config.useSingleConnection().setAddress("127.0.0.1:6379");

        // but using a redis server on redislabs.com does not work:
        config.useSingleServer()
            .setAddress("pub-redis-19585.us-east-1-4.3.ec2.garantiadata.com:19585")
            .setPassword("test");

        Redisson redisson = Redisson.create(config);

        StoredSession storedSession = new StoredSession();
        String uuid = UUID.randomUUID().toString();
        storedSession.setId(uuid);
        storedSession.setMaxAge(20);
        storedSession.setCreationTime(System.currentTimeMillis());
        storedSession.setLastAccessTime(storedSession.getCreationTime());

        redisson.getBucket(uuid).set(storedSession, storedSession.getTTL(), TimeUnit.SECONDS);

        RBucket<StoredSession> bucket = redisson.<StoredSession>getBucket(uuid);
        storedSession = bucket.get();

        assertNotNull(storedSession);
    }

}
