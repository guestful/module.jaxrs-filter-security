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
import com.guestful.jaxrs.security.session.JedisJsonSessionRepository;
import com.guestful.jaxrs.security.session.JedisKryoSessionRepository;
import com.guestful.jaxrs.security.session.SessionRepository;
import com.guestful.jaxrs.security.session.StoredSession;
import com.guestful.json.JsonMapper;
import com.guestful.json.groovy.GroovyJsonMapper;
import com.guestful.simplepool.BoundedObjectPool;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.redisson.Config;
import org.redisson.Redisson;
import org.redisson.codec.KryoCodec;
import org.redisson.core.RBucket;
import redis.clients.jedis.JedisPool;

import java.lang.reflect.Method;
import java.util.Collection;
import java.util.UUID;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.*;

/**
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
@RunWith(JUnit4.class)
public final class RedissonSessionRepositoryTest {

    @Test
    public void test() throws Exception {
        // jedis
        JedisPool jedisPool = new JedisPool("127.0.0.1", 6379);

        // redisson
        Config config = new Config().setCodec(new KryoCodec());
        config.useSingleServer().setAddress("127.0.0.1:6379");
        Redisson redisson = Redisson.create(config);

        // flush db
        jedisPool.getResource().flushDB();

        StoredSession storedSession1 = new StoredSession();
        String uuid1 = UUID.randomUUID().toString();
        storedSession1.setPrincipal(uuid1);
        storedSession1.setId(uuid1);
        storedSession1.setMaxAge(20);
        storedSession1.setCreationTime(System.currentTimeMillis());
        storedSession1.setLastAccessTime(storedSession1.getCreationTime());

        StoredSession storedSession2 = new StoredSession();
        String uuid2 = UUID.randomUUID().toString();
        storedSession2.setPrincipal(uuid2);
        storedSession2.setId(uuid2);
        storedSession2.setMaxAge(20);
        storedSession2.setCreationTime(System.currentTimeMillis());
        storedSession2.setLastAccessTime(storedSession1.getCreationTime());
        storedSession2.setAttribute("key1", "val");
        storedSession2.setAttribute("key2", 3);

        redisson.getBucket(uuid1).set(storedSession1, storedSession1.getTTL(), TimeUnit.SECONDS);
        RBucket<StoredSession> bucket = redisson.<StoredSession>getBucket(uuid1);
        storedSession1 = bucket.get();
        assertNotNull(storedSession1);

        SessionRepository sessionRepository = new JedisKryoSessionRepository(jedisPool, new BoundedObjectPool<>(5, 60, 30000, Kryo::new));
        //SessionRepository sessionRepository = new RedissonSessionRepository(redisson);
        sessionRepository.saveSession("", storedSession1);
        sessionRepository.saveSession("", storedSession2);

        assertEquals(storedSession1.getPrincipal(), sessionRepository.findSession("", storedSession1.getId()).getPrincipal());

        Collection<String> sessions = sessionRepository.findSessions("")
            .map(StoredSession::getPrincipal)
            .collect(ConcurrentLinkedQueue::new, ConcurrentLinkedQueue::add, ConcurrentLinkedQueue::addAll);
        assertEquals(2, sessions.size());
        assertTrue(sessions.contains(uuid1));
        assertTrue(sessions.contains(uuid2));

        JsonMapper mapper = new GroovyJsonMapper();
        JedisJsonSessionRepository jedisJsonSessionRepository = new JedisJsonSessionRepository(jedisPool, mapper);
        jedisJsonSessionRepository.saveSession("json", storedSession2);
        StoredSession storedSession3 = jedisJsonSessionRepository.findSession("json", uuid2);
        //assertEquals(mapper.toJson(storedSession2), mapper.toJson(storedSession3));
        assertEquals(storedSession2.toString(), storedSession3.toString());
        for (Method method : StoredSession.class.getDeclaredMethods()) {
            if (method.getParameterCount() == 0 && method.getReturnType() != Void.class) {
                System.out.println(method.getName());
                assertEquals(method.invoke(storedSession2), method.invoke(storedSession3));
            }
        }
    }

}
