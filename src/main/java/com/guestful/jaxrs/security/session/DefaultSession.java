/**
 * Copyright (C) 2013 Guestful (info@guestful.com)
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.guestful.jaxrs.security.session;

import com.guestful.jaxrs.security.subject.Subject;
import com.guestful.jaxrs.security.util.Crypto;

import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * date 2014-05-26
 *
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public class DefaultSession implements Session {

    private final String id;
    private final String origin;
    private final String lastOrigin;
    private final String userAgent;
    private final String lastUserAgent;
    private final int maxAge;
    private final boolean isNew;
    private final long creationTime;
    private final long lastAccessTime;
    private final Map<String, Object> attributes = new ConcurrentHashMap<>();

    public DefaultSession() {
        this.id = Crypto.uuid();
        this.creationTime = System.currentTimeMillis();
        this.maxAge = -1;
        this.isNew = true;
        this.origin = null;
        this.userAgent = null;
        this.lastAccessTime = this.creationTime;
        this.lastOrigin = null;
        this.lastUserAgent = null;
    }

    public DefaultSession(Subject subject, int maxAge) {
        this.id = Crypto.uuid();
        this.creationTime = System.currentTimeMillis();
        this.maxAge = maxAge;
        this.isNew = true;
        this.origin = subject == null ? null : subject.getOrigin();
        this.userAgent = subject == null ? null : subject.getUserAgent();
        this.lastAccessTime = this.creationTime;
        this.lastOrigin = this.origin;
        this.lastUserAgent = this.userAgent;
    }

    public DefaultSession(StoredSession storedSession) {
        this.id = storedSession.getId();
        this.creationTime = storedSession.getCreationTime();
        this.maxAge = storedSession.getMaxAge();
        this.origin = storedSession.getOrigin();
        this.userAgent = storedSession.getUserAgent();
        this.attributes.putAll(storedSession.getAttributes());
        this.lastAccessTime = storedSession.getLastAccessTime();
        this.lastOrigin = storedSession.getLastOrigin();
        this.lastUserAgent = storedSession.getLastUserAgent();
        this.isNew = false;
    }

    @Override
    public String getLastOrigin() {
        return lastOrigin;
    }

    @Override
    public String getLastUserAgent() {
        return lastUserAgent;
    }

    @Override
    public String getUserAgent() {
        return userAgent;
    }

    @Override
    public boolean isNew() {
        return isNew;
    }

    @Override
    public String getId() {
        return id;
    }

    @Override
    public String getOrigin() {
        return origin;
    }

    @Override
    public int getMaxAge() {
        return maxAge;
    }

    @Override
    public long getCreationTime() {
        return creationTime;
    }

    @Override
    public long getLastAccessTime() {
        return lastAccessTime;
    }

    @Override
    public void setAttribute(String key, Object value) {
        attributes.put(key, value);
    }

    @Override
    public Object getAttribute(String key, Object value) {
        return attributes.get(key);
    }

    @Override
    public Map<String, Object> getAttributes() {
        return Collections.unmodifiableMap(attributes);
    }

    @Override
    public String toString() {
        return "{" +
            "id='" + id + '\'' +
            ", origin='" + origin + '\'' +
            ", creationTime=" + creationTime +
            ", maxAge=" + maxAge +
            ", isNew=" + isNew +
            ", lastAccessTime=" + lastAccessTime +
            '}';
    }

}
