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

import com.guestful.jaxrs.security.token.AuthenticationToken;

import javax.ws.rs.core.SecurityContext;
import java.security.Principal;

/**
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public interface SubjectSecurityContext extends SecurityContext {

    default Subject getSubject() {
        return getSubject("");
    }

    default Subject getSubject(String system) {
        return SubjectContext.getSubject(system);
    }

    @Override
    default Principal getUserPrincipal() {
        return getUserPrincipal("");
    }

    default Principal getUserPrincipal(String system) {
        return getSubject(system).getPrincipal();
    }

    @Override
    default boolean isUserInRole(String role) {
        return isUserInRole("", role);
    }

    default boolean isUserInRole(String system, String role) {
        return getSubject(system).hasRole(role);
    }

    @Override
    default String getAuthenticationScheme() {
        return getAuthenticationScheme("");
    }

    default String getAuthenticationScheme(String system) {
        AuthenticationToken token = getSubject(system).getAuthenticationToken();
        return token == null ? null : token.getScheme();
    }

    @Override
    boolean isSecure();

}
