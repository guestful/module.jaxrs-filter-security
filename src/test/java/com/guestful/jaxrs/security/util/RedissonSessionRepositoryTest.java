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
import com.guestful.jaxrs.security.realm.StringPrincipal;
import com.guestful.jaxrs.security.session.RedissonSessionRepository;
import com.guestful.jaxrs.security.session.StoredSession;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.redisson.Config;
import org.redisson.Redisson;
import org.redisson.codec.KryoCodec;
import org.redisson.core.RBucket;

import java.util.Collection;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.junit.Assert.*;

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
                return new Kryo();
            }
        };
        Config config = new Config();
        config.setCodec(new KryoCodec(kryoPool));

        // using local connection, it works:
        config.useSingleServer().setAddress("127.0.0.1:6379");

        // but using a redis server on redislabs.com does not work:
        /*config.useSingleServer()
            .setAddress(System.getenv("REDIS_ADDRESS"))
            .setPassword(System.getenv("REDIS_AUTH"));*/

        Redisson redisson = Redisson.create(config);

        StoredSession storedSession1 = new StoredSession();
        String uuid1 = UUID.randomUUID().toString();
        storedSession1.setPrincipal(new StringPrincipal(uuid1));
        storedSession1.setId(uuid1);
        storedSession1.setMaxAge(20);
        storedSession1.setCreationTime(System.currentTimeMillis());
        storedSession1.setLastAccessTime(storedSession1.getCreationTime());

        redisson.getBucket(uuid1).set(storedSession1, storedSession1.getTTL(), TimeUnit.SECONDS);

        RBucket<StoredSession> bucket = redisson.<StoredSession>getBucket(uuid1);
        storedSession1 = bucket.get();

        assertNotNull(storedSession1);

        StoredSession storedSession2 = new StoredSession();
        String uuid2 = UUID.randomUUID().toString();
        storedSession2.setPrincipal(new StringPrincipal(uuid2));
        storedSession2.setId(uuid2);
        storedSession2.setMaxAge(20);
        storedSession2.setCreationTime(System.currentTimeMillis());
        storedSession2.setLastAccessTime(storedSession1.getCreationTime());

        RedissonSessionRepository sessionRepository = new RedissonSessionRepository(redisson);
        sessionRepository.saveSession(storedSession1);
        sessionRepository.saveSession(storedSession2);

        assertEquals(storedSession1.getPrincipal(), sessionRepository.findSession(storedSession1.getId()).getPrincipal());

        Collection<String> sessions = sessionRepository.findSessions()
            .stream()
            .map(st -> st.getPrincipal().getName())
            .collect(Collectors.toList());
        assertEquals(2, sessions.size());
        assertTrue(sessions.contains(uuid1));
        assertTrue(sessions.contains(uuid2));
    }

}
