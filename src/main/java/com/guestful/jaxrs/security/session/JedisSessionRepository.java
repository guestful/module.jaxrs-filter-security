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
package com.guestful.jaxrs.security.session;

import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.io.Input;
import com.esotericsoftware.kryo.io.Output;
import com.guestful.simplepool.ObjectPool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.concurrent.TimeoutException;
import java.util.function.Function;
import java.util.stream.Stream;

/**
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public class JedisSessionRepository implements SessionRepository {

    private static final Logger LOGGER = LoggerFactory.getLogger(JedisSessionRepository.class);
    private static final String PREFIX = "api:sessions:";
    private final JedisPool jedisPool;
    private final ObjectPool<Kryo> kryoPool;

    public JedisSessionRepository(JedisPool jedisPool, ObjectPool<Kryo> kryoPool) {
        this.jedisPool = jedisPool;
        this.kryoPool = kryoPool;
    }

    @Override
    public void saveSession(String system, StoredSession storedSession) {
        String key = key(system, storedSession.getId());
        LOGGER.trace("saveSession() {}={}", key, storedSession);
        byte[] data = encode(storedSession);
        redis(jedis -> {
            jedis.setex(key.getBytes(StandardCharsets.UTF_8), storedSession.getTTL(), data);
            return null;
        });
    }

    @Override
    public void removeSession(String system, String sessionId) {
        String key = key(system, sessionId);
        LOGGER.trace("removeSession() {}", key);
        redis(jedis -> {
            jedis.del(key.getBytes(StandardCharsets.UTF_8));
            return null;
        });
    }

    @Override
    public StoredSession findSession(String system, String sessionId) {
        String key = key(system, sessionId);
        LOGGER.trace("findSession() {}", key);
        byte[] b = redis(jedis -> jedis.get(key.getBytes(StandardCharsets.UTF_8)));
        try {
            return decode(b);
        } catch (DecodingException e) {
            removeSession(system, sessionId);
            return null;
        }
    }

    @Override
    public Stream<StoredSession> findSessions(String system) {
        String key = key(system, "*");
        LOGGER.trace("findSessions() {}", key);
        return redis(jedis -> {
            Set<byte[]> keySet = jedis.keys(key.getBytes(StandardCharsets.UTF_8));
            byte[][] keys = keySet.toArray(new byte[keySet.size()][]);
            return jedis.mget(keys);
        }).parallelStream().flatMap(bytes -> {
            try {
                return Stream.of(decode(bytes));
            } catch (DecodingException e) {
                return Stream.empty();
            }
        });
    }

    private <T> T redis(Function<Jedis, T> consumer) {
        Jedis jedis = jedisPool.getResource();
        try {
            T o = consumer.apply(jedis);
            jedisPool.returnResource(jedis);
            return o;
        } catch (Exception e) {
            jedisPool.returnBrokenResource(jedis);
            throw e;
        }
    }

    private String key(String system, String id) {
        return system == null || system.equals("") ? (PREFIX + id) : (PREFIX + system + ":" + id);
    }

    private byte[] encode(StoredSession storedSession) throws SessionRepositoryException {
        Kryo kryo = null;
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            Output output = new Output(baos);
            kryo = kryoPool.borrow();
            kryo.writeClassAndObject(output, storedSession);
            output.close();
            return baos.toByteArray();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new SessionRepositoryException("Unable to encode session " + storedSession + ": " + e.getMessage(), e);
        } catch (TimeoutException e) {
            throw new SessionRepositoryException("Unable to encode session " + storedSession + ": " + e.getMessage(), e);
        } finally {
            if (kryo != null) {
                kryoPool.yield(kryo);
            }
        }
    }

    private StoredSession decode(byte[] bytes) throws SessionRepositoryException, DecodingException {
        if (bytes == null) return null;
        Kryo kryo = null;
        try {
            kryo = kryoPool.borrow();
            return (StoredSession) kryo.readClassAndObject(new Input(bytes));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new SessionRepositoryException("Unable to decode session: " + e.getMessage(), e);
        } catch (TimeoutException e) {
            throw new SessionRepositoryException("Unable to decode session: " + e.getMessage(), e);
        } catch (Exception e) {
            // decoding issue
            throw new DecodingException(e);
        } finally {
            if (kryo != null) {
                kryoPool.yield(kryo);
            }
        }
    }

    private static final class DecodingException extends RuntimeException {
        public DecodingException(Throwable cause) {
            super(cause);
        }
    }

}
