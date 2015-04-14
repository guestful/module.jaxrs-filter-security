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
package com.guestful.jaxrs.security.subject;

import com.guestful.jaxrs.security.session.DefaultSession;
import com.guestful.jaxrs.security.session.Session;
import com.guestful.jaxrs.security.token.AuthenticationToken;

import javax.ws.rs.container.ContainerRequestContext;
import java.security.Principal;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
class AnonymousSubject implements Subject {

    private final Map<String, Object> attributes = new ConcurrentHashMap<>();
    private Session session;
    private final String system;

    public AnonymousSubject() {
        this("");
    }

    public AnonymousSubject(String system) {
        this.system = system;
    }

    @Override
    public String getSystem() {
        return system;
    }

    @Override
    public Principal getPrincipal() {
        return null;
    }

    @Override
    public Session getSession(boolean create) {
        if (session == null && create) {
            session = new DefaultSession(system);
        }
        return session;
    }

    @Override
    public boolean hasRoles(Collection<String> roles) {
        return false;
    }

    @Override
    public boolean isPermitted(Collection<String> permissions) {
        return false;
    }

    @Override
    public ContainerRequestContext getRequest() {
        return null;
    }

    @Override
    public AuthenticationToken getAuthenticationToken() {
        return null;
    }

    @Override
    public void setAttribute(String name, Object value) {
        attributes.put(name, value);
    }

    @Override
    public Object getAttribute(String name) {
        return attributes.get(name);
    }

    @Override
    public Map<String, Object> getAttributes() {
        return Collections.unmodifiableMap(attributes);
    }

    @Override
    public String getOrigin() {
        return null;
    }

    @Override
    public String getUserAgent() {
        return null;
    }

    @Override
    public String toString() {
        return "<anonymous>";
    }

}
