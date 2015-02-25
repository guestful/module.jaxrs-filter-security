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

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.inject.Singleton;
import java.util.Collection;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.logging.Logger;

/**
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
@Singleton
public class MemorySessionRepository implements SessionRepository {

    private static final Logger LOGGER = Logger.getLogger(MemorySessionRepository.class.getName());

    private final ConcurrentMap<String, StoredSession> sessions = new ConcurrentHashMap<>();
    private Thread scavenger;

    @PostConstruct
    public void init() {
        if (scavenger == null) {
            scavenger = new Thread(MemorySessionRepository.class.getSimpleName() + "-Scavenger") {
                @Override
                public void run() {
                    try {
                        while (!Thread.currentThread().isInterrupted()) {
                            Thread.sleep(60000);
                            LOGGER.finest("scavenger() searching for expired sessions (" + sessions.size() + " sessions in cache)");
                            sessions.values().stream().filter(StoredSession::isExpired).forEach(storedSession -> {
                                LOGGER.finest("scavenger() removing expired session " + storedSession.getId());
                                sessions.remove(storedSession.getId(), storedSession);
                            });
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    } finally {
                        scavenger = null;
                    }
                }
            };
            LOGGER.finest("init() Starting scavenger thread " + scavenger.getName());
            scavenger.start();
        }
    }

    @PreDestroy
    public void close() {
        if (scavenger != null) {
            scavenger.interrupt();
            scavenger = null;
        }
    }

    @Override
    public void saveSession(StoredSession storedSession) {
        LOGGER.finest(storedSession.getPrincipal() + "  Saving session " + storedSession.getId());
        sessions.put(storedSession.getId(), storedSession);
    }

    @Override
    public void removeSession(String sessionId) {
        LOGGER.finest("removeSession() " + sessionId);
        sessions.remove(sessionId);
    }

    @Override
    public StoredSession findSession(String sessionId) {
        return sessions.get(sessionId);
    }

    @Override
    public Collection<StoredSession> findSessions() {
        return sessions.values();
    }

}
