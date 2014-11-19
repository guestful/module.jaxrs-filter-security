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
    public void removeSession(Principal principal, String id) {
        LOGGER.finest(principal + " Removing session " + id);
        Jedis jedis = null;
        boolean jedisFailure = false;
        try {
            jedis = jedisPool.getResource();
            byte[] key = key(id);
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
    public StoredSession findSession(String id) {
        Jedis jedis = null;
        boolean jedisfailure = false;
        try {
            jedis = jedisPool.getResource();
            byte[] k = key(id);
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
                throw new SessionRepositoryException("Unable to save session " + id + ": " + e.getMessage(), e);
            } catch (Exception e) {
                LOGGER.log(Level.WARNING, "Removing malformed session " + id + ": " + e.getMessage(), e);
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
