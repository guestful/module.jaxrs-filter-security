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

import java.io.Serializable;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public class StoredSession implements Serializable, Expirable {

    private static final long serialVersionUID = 3078945930895997491L;

    private boolean isNew;
    private String principal;
    private String id;
    private String origin;
    private String lastOrigin;
    private String userAgent;
    private String lastUserAgent;
    private int maxAge;
    private long creationTime;
    private long lastAccessTime;
    private Map<String, Object> attributes = new LinkedHashMap<>();

    public StoredSession() {
    }

    private StoredSession(Subject subject) {
        // save session attrs
        Session session = subject.getSession(false);
        if (session == null) throw new NullPointerException();

        setNew(session.isNew());
        setAttributes(session.getAttributes());
        setCreationTime(session.getCreationTime());
        setId(session.getId());
        setMaxAge(session.getMaxAge());
        setOrigin(session.getOrigin());
        setUserAgent(session.getUserAgent());
        setPrincipal(subject.getPrincipal().getName());

        setLastAccessTime(System.currentTimeMillis());
        setLastOrigin(subject.getOrigin());
        setLastUserAgent(subject.getUserAgent());
    }

    @Override
    public int getMaxAge() {
        return maxAge;
    }

    @Override
    public long getLastAccessTime() {
        return lastAccessTime;
    }

    public String getLastOrigin() {
        return lastOrigin;
    }

    public void setLastOrigin(String lastOrigin) {
        this.lastOrigin = lastOrigin;
    }

    public String getLastUserAgent() {
        return lastUserAgent;
    }

    public void setLastUserAgent(String lastUserAgent) {
        this.lastUserAgent = lastUserAgent;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public void setUserAgent(String userAgent) {
        this.userAgent = userAgent;
    }

    public String getId() {
        return id;
    }

    public String getOrigin() {
        return origin;
    }

    public long getCreationTime() {
        return creationTime;
    }

    public String toString() {
        return getId();
    }

    public void setAttribute(String key, Object value) {
        attributes.put(key, value);
    }

    public Object getAttribute(String key, Object value) {
        return attributes.get(key);
    }

    public Map<String, Object> getAttributes() {
        return attributes;
    }

    public boolean isNew() {
        return isNew;
    }

    public void setNew(boolean isNew) {
        this.isNew = isNew;
    }

    public void setCreationTime(long creationTime) {
        this.creationTime = creationTime;
    }

    public void setLastAccessTime(long lastAccessTime) {
        this.lastAccessTime = lastAccessTime;
    }

    public void setAttributes(Map<String, Object> attributes) {
        this.attributes = new LinkedHashMap<>(attributes);
    }

    public String getPrincipal() {
        return principal;
    }

    public void setPrincipal(String principal) {
        this.principal = principal;
    }

    public void setId(String id) {
        this.id = id;
    }

    public void setOrigin(String origin) {
        this.origin = origin;
    }

    public void setMaxAge(int maxAge) {
        this.maxAge = maxAge;
    }

    public static StoredSession accessed(Subject subject) {
        return new StoredSession(subject);
    }

}
