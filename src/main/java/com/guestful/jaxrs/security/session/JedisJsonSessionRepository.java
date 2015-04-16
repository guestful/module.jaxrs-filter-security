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

import com.guestful.json.JsonMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Stream;

/**
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public class JedisJsonSessionRepository implements SessionRepository {

    private static final Logger LOGGER = LoggerFactory.getLogger(JedisJsonSessionRepository.class);
    private static final String PREFIX = "api:sessions:";
    private final JedisPool jedisPool;
    private final JsonMapper jsonMapper;

    public JedisJsonSessionRepository(JedisPool jedisPool, JsonMapper jsonMapper) {
        this.jedisPool = jedisPool;
        this.jsonMapper = jsonMapper;
    }

    @Override
    public void saveSession(String system, StoredSession storedSession) {
        String key = key(system, storedSession.getId());
        LOGGER.trace("saveSession() {}={}", key, storedSession);
        String data = encode(storedSession);
        redis(jedis -> {
            jedis.setex(key, storedSession.getTTL(), data);
            return null;
        });
    }

    @Override
    public void removeSession(String system, String sessionId) {
        String key = key(system, sessionId);
        LOGGER.trace("removeSession() {}", key);
        redis(jedis -> {
            jedis.del(key);
            return null;
        });
    }

    @Override
    public StoredSession findSession(String system, String sessionId) {
        String key = key(system, sessionId);
        LOGGER.trace("findSession() {}", key);
        String data = redis(jedis -> jedis.get(key));
        try {
            return decode(data);
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
            Set<String> keySet = jedis.keys(key);
            String[] keys = keySet.toArray(new String[keySet.size()]);
            return jedis.mget(keys);
        }).parallelStream().flatMap(data -> {
            try {
                return Stream.of(decode(data));
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

    private String encode(StoredSession storedSession) throws SessionRepositoryException {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("isNew", storedSession.isNew());
        map.put("principal", storedSession.getPrincipal());
        map.put("id", storedSession.getId());
        map.put("origin", storedSession.getOrigin());
        map.put("lastOrigin", storedSession.getLastOrigin());
        map.put("userAgent", storedSession.getUserAgent());
        map.put("lastUserAgent", storedSession.getLastUserAgent());
        map.put("maxAge", storedSession.getMaxAge());
        map.put("creationTime", storedSession.getCreationTime());
        map.put("lastAccessTime", storedSession.getLastAccessTime());
        map.put("attributes", storedSession.getAttributes());
        return jsonMapper.toJson(map);
    }

    @SuppressWarnings("unchecked")
    private StoredSession decode(String data) throws SessionRepositoryException, DecodingException {
        try {
            Map map = jsonMapper.fromJson(data, Map.class);
            StoredSession session = new StoredSession();
            session.setNew((Boolean) map.get("isNew"));
            session.setPrincipal((String) map.get("principal"));
            session.setId((String) map.get("id"));
            session.setOrigin((String) map.get("origin"));
            session.setLastOrigin((String) map.get("lastOrigin"));
            session.setUserAgent((String) map.get("userAgent"));
            session.setLastUserAgent((String) map.get("lastUserAgent"));
            session.setMaxAge((Integer) map.get("maxAge"));
            session.setCreationTime((Long) map.get("creationTime"));
            session.setLastAccessTime((Long) map.get("lastAccessTime"));
            session.setAttributes((Map<String, Object>) map.get("attributes"));
            return session;
        } catch (Exception e) {
            // decoding issue
            LOGGER.trace("decode() ERROR: {}, DATA: {}", e.getMessage(), data);
            throw new DecodingException(e);
        }
    }

    private static final class DecodingException extends RuntimeException {
        public DecodingException(Throwable cause) {
            super(cause);
        }
    }

}
