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
package com.guestful.jaxrs.security.subject;

import com.guestful.jaxrs.security.LoginContext;
import com.guestful.jaxrs.security.session.ConnectedSession;
import com.guestful.jaxrs.security.token.AuthenticationToken;

import javax.ws.rs.container.ContainerRequestContext;
import java.util.Arrays;
import java.util.Collection;

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

    default String getSystem() {
        return getAuthenticationToken() == null ? null : getAuthenticationToken().getSystem();
    }

    void setAttribute(String name, Object value);

    Object getAttribute(String name);

    default boolean isRemembered() {
        return getPrincipal() != null && getAuthenticationToken() != null && !getAuthenticationToken().isAuthenticationRequired();
    }

    default boolean isAuthenticated() {
        return getPrincipal() != null && getAuthenticationToken() != null && getAuthenticationToken().isAuthenticationRequired();
    }

    default void logout() {
        SubjectContext.logout(this);
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
