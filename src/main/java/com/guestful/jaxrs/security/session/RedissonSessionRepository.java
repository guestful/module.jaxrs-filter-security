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

import org.redisson.Redisson;
import org.redisson.core.RBucket;

import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public class RedissonSessionRepository implements SessionRepository {

    private static final Logger LOGGER = Logger.getLogger(RedissonSessionRepository.class.getName());
    private static final String PREFIX = "api:sessions:";
    private final Redisson redisson;

    public RedissonSessionRepository(Redisson redisson) {
        this.redisson = redisson;
    }

    @Override
    public void saveSession(StoredSession storedSession) {
        LOGGER.finest(storedSession.getPrincipal() + "  Saving session " + storedSession.getId());
        redisson.getBucket(PREFIX + storedSession.getId()).set(storedSession, storedSession.getTTL(), TimeUnit.SECONDS);
    }

    @Override
    public void removeSession(String sessionId) {
        LOGGER.finest("removeSession() " + sessionId);
        redisson.getBucket(PREFIX + sessionId).delete();
    }

    @Override
    public StoredSession findSession(String sessionId) {
        RBucket<StoredSession> bucket = redisson.<StoredSession>getBucket(PREFIX + sessionId);
        try {
            return bucket.get();
        } catch (RuntimeException e) {
            LOGGER.log(Level.WARNING, "Removing malformed session " + sessionId + ": " + e.getMessage(), e);
            bucket.delete();
            return null;
        }
    }

}
