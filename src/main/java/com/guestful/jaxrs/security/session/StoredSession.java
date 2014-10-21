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

import com.guestful.jaxrs.security.subject.Subject;

import java.io.Serializable;
import java.security.Principal;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 * s@date 2014-05-27
 */
public class StoredSession implements Session, Serializable {

    private static final long serialVersionUID = 3078945930695997491L;

    private boolean isNew;
    private Principal principal;
    private String id;
    private String origin;
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
        setPrincipal(subject.getPrincipal());

        setLastAccessTime(System.currentTimeMillis());
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
    public String toString() {
        return getId();
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
        return attributes;
    }

    @Override
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

    public Principal getPrincipal() {
        return principal;
    }

    public void setPrincipal(Principal principal) {
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
