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

import com.guestful.jaxrs.security.LoginContext;
import com.guestful.jaxrs.security.session.ConnectedSession;
import com.guestful.jaxrs.security.token.AuthenticationToken;

import javax.ws.rs.container.ContainerRequestContext;
import java.util.Arrays;
import java.util.Collection;
import java.util.concurrent.Callable;

/**
 * date 2014-05-23
 *
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public interface Subject extends LoginContext {

    boolean hasRoles(Collection<String> roles);

    boolean isPermitted(Collection<String> permissions);

    ContainerRequestContext getRequest();

    AuthenticationToken getAuthenticationToken();

    void setAttribute(String name, Object value);

    Object getAttribute(String name);

    default boolean isRemembered() {
        return getPrincipal() != null && getAuthenticationToken() != null && !isAuthenticated();
    }

    default boolean isAuthenticated() {
        return getPrincipal() != null && getAuthenticationToken() != null && getAuthenticationToken().isAuthenticationRequired();
    }

    default void logout() {
        SubjectContext.logout(this);
    }

    default Runnable associateWith(Runnable r) {
        Subject that = this;
        return new Runnable() {
            @Override
            public void run() {
                Subject subject = SubjectContext.getSubject(false);
                SubjectContext.setCurrentSubject(that);
                try {
                    r.run();
                } finally {
                    SubjectContext.clearCurrentSubject();
                    if (subject != null) {
                        SubjectContext.setCurrentSubject(subject);
                    }
                }
            }
        };
    }

    default <V> Callable<V> associateWith(Callable<V> c) {
        Subject that = this;
        return new Callable<V>() {
            @Override
            public V call() throws Exception {
                Subject subject = SubjectContext.getSubject(false);
                SubjectContext.setCurrentSubject(that);
                try {
                    return c.call();
                } finally {
                    SubjectContext.clearCurrentSubject();
                    if (subject != null) {
                        SubjectContext.setCurrentSubject(subject);
                    }
                }
            }
        };
    }

    default boolean isAnonymous() {
        return !isAuthenticated() && !isRemembered();
    }

    default boolean isPermitted(String permission) {
        return isPermitted(Arrays.asList(permission));
    }

    default boolean hasRole(String role) {
        return hasRoles(Arrays.asList(role));
    }

    default void accessed() {
        SubjectContext.accessed(this);
    }

    default Collection<ConnectedSession> getConnectedSessions() {
        return SubjectContext.getConnectedSessions(this);
    }

}
