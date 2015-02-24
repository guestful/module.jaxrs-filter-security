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
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeoutException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public class JedisSessionRepository implements SessionRepository {

    private static final Logger LOGGER = Logger.getLogger(JedisSessionRepository.class.getName());
    private static final String PREFIX = "api:sessions:";
    private final JedisPool jedisPool;
    private final ObjectPool<Kryo> kryoPool;

    public JedisSessionRepository(JedisPool jedisPool, ObjectPool<Kryo> kryoPool) {
        this.jedisPool = jedisPool;
        this.kryoPool = kryoPool;
    }

    @Override
    public void saveSession(StoredSession storedSession) {
        LOGGER.finest(storedSession.getPrincipal() + "  Saving session " + storedSession.getId());
        Jedis jedis = null;
        boolean jedisFailure = false;
        try {
            jedis = jedisPool.getResource();
            byte[] key = key(storedSession.getId());
            byte[] data = encode(storedSession);
            try {
                jedis.setex(key, storedSession.getTTL(), data);
            } catch (Exception je) {
                jedisFailure = true;
                throw je;
            }
        } catch (InterruptedException | TimeoutException e) {
            throw new SessionRepositoryException("Unable to save session " + storedSession.getId() + ": " + e.getMessage(), e);
        } finally {
            if (jedisFailure) {
                jedisPool.returnBrokenResource(jedis);
            } else {
                jedisPool.returnResource(jedis);
            }
        }
    }

    @Override
    public void removeSession(String sessionId) {
        LOGGER.finest("removeSession() " + sessionId);
        Jedis jedis = null;
        boolean jedisFailure = false;
        try {
            jedis = jedisPool.getResource();
            byte[] key = key(sessionId);
            try {
                jedis.del(key);
            } catch (Exception je) {
                jedisFailure = true;
                throw je;
            }
        } finally {
            if (jedisFailure) {
                jedisPool.returnBrokenResource(jedis);
            } else {
                jedisPool.returnResource(jedis);
            }
        }
    }

    @Override
    public StoredSession findSession(String sessionId) {
        Jedis jedis = null;
        boolean jedisfailure = false;
        try {
            jedis = jedisPool.getResource();
            byte[] k = key(sessionId);
            byte[] bytes;
            try {
                bytes = jedis.get(k);
            } catch (Exception je) {
                jedisfailure = true;
                throw je;
            }
            try {
                return (StoredSession) decode(bytes);
            } catch (InterruptedException | TimeoutException e) {
                throw new SessionRepositoryException("Unable to save session " + sessionId + ": " + e.getMessage(), e);
            } catch (Exception e) {
                LOGGER.log(Level.WARNING, "Removing malformed session " + sessionId + ": " + e.getMessage(), e);
                try {
                    jedis.del(k);
                } catch (Exception je) {
                    jedisfailure = true;
                }
                return null;
            }
        } finally {
            if (jedisfailure) {
                jedisPool.returnBrokenResource(jedis);
            } else {
                jedisPool.returnResource(jedis);
            }
        }
    }

    @Override
    public Collection<StoredSession> findConnectedSessions(Principal principal) {
        Jedis jedis = null;
        boolean jedisfailure = false;
        Collection<StoredSession> storedSessions = new ArrayList<>();
        try {
            jedis = jedisPool.getResource();
            List<byte[]> vals;
            byte[][] keys;
            try {
                Set<byte[]> keySet = jedis.keys(key("*"));
                keys = keySet.toArray(new byte[0][]);
                vals = jedis.mget(keys);
            } catch (Exception je) {
                jedisfailure = true;
                throw je;
            }
            for (int i = 0; i < keys.length; i++) {
                byte[] key = keys[i];
                byte[] bytes = vals.get(i);
                try {
                    storedSessions.add((StoredSession) decode(bytes));
                } catch (Exception e) {
                    LOGGER.log(Level.WARNING, "Removing malformed session " + new String(key) + ": " + e.getMessage(), e);
                    try {
                        jedis.del(key);
                    } catch (Exception je) {
                        jedisfailure = true;
                    }
                }
            }
        } finally {
            if (jedisfailure) {
                jedisPool.returnBrokenResource(jedis);
            } else {
                jedisPool.returnResource(jedis);
            }
        }
        return storedSessions;
    }

    private Object decode(byte[] bytes) throws TimeoutException, InterruptedException {
        if (bytes == null) return null;
        Kryo kryo = null;
        try {
            kryo = kryoPool.borrow();
            return kryo.readClassAndObject(new Input(bytes));
        } finally {
            if (kryo != null) {
                kryoPool.yield(kryo);
            }
        }
    }

    private byte[] key(String id) {
        return (PREFIX + id).getBytes(StandardCharsets.UTF_8);
    }

    private byte[] encode(Object value) throws TimeoutException, InterruptedException {
        Kryo kryo = null;
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            Output output = new Output(baos);
            kryo = kryoPool.borrow();
            kryo.writeClassAndObject(output, value);
            output.close();
            return baos.toByteArray();
        } finally {
            if (kryo != null) {
                kryoPool.yield(kryo);
            }
        }
    }

}
