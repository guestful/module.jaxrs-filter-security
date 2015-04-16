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
package com.guestful.jaxrs.security.filter;

import com.guestful.jaxrs.security.annotation.Authenticated;
import com.guestful.jaxrs.security.subject.Subject;
import com.guestful.jaxrs.security.subject.SubjectContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Priority;
import javax.annotation.security.DenyAll;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.ws.rs.ForbiddenException;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.DynamicFeature;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.FeatureContext;
import java.io.IOException;
import java.lang.reflect.Method;
import java.util.Objects;

/**
 * A {@link DynamicFeature} supporting the {@code javax.annotation.security.RolesAllowed},
 * {@code javax.annotation.security.PermitAll} and {@code javax.annotation.security.DenyAll}
 * on resource methods and sub-resource methods.
 * <p>
 * The {@link javax.ws.rs.core.SecurityContext} is utilized, using the
 * {@link javax.ws.rs.core.SecurityContext#isUserInRole(String) } method,
 * to ascertain if the user is in one
 * of the roles declared in by a {@code &#64;RolesAllowed}. If a user is in none of
 * the declared roles then a 403 (Forbidden) response is returned.
 * <p>
 * If the {@code &#64;DenyAll} annotation is declared then a 403 (Forbidden) response
 * is returned.
 * <p>
 * If the {@code &#64;PermitAll} annotation is declared and is not overridden then
 * this filter will not be applied.
 *
 * @author Paul Sandoz (paul.sandoz at oracle.com)
 * @author Martin Matula (martin.matula at oracle.com)
 */
public class RolesAllowedFeature implements DynamicFeature {

    private static final Logger LOGGER = LoggerFactory.getLogger(RolesAllowedFeature.class);

    @Override
    public void configure(final ResourceInfo resourceInfo, final FeatureContext configuration) {
        Method am = resourceInfo.getResourceMethod();

        Authenticated authenticated = am.getAnnotation(Authenticated.class);
        if (authenticated == null) {
            authenticated = resourceInfo.getResourceClass().getAnnotation(Authenticated.class);
        }
        String system = authenticated == null ? null : authenticated.value();

        // DenyAll on the method take precedence over RolesAllowed and PermitAll
        if (am.isAnnotationPresent(DenyAll.class)) {
            configuration.register(new RolesAllowedRequestFilter(Objects.requireNonNull(system, "@Permissions found on " + am + " but no @Authenticated found")));
            return;
        }

        // RolesAllowed on the method takes precedence over PermitAll
        RolesAllowed ra = am.getAnnotation(RolesAllowed.class);
        if (ra != null) {
            configuration.register(new RolesAllowedRequestFilter(
                Objects.requireNonNull(system, "@Permissions found on " + am + " but no @Authenticated found"),
                ra.value()));
            return;
        }

        // PermitAll takes precedence over RolesAllowed on the class
        if (am.isAnnotationPresent(PermitAll.class)) {
            // Do nothing.
            return;
        }

        // DenyAll can't be attached to classes

        // RolesAllowed on the class takes precedence over PermitAll
        ra = resourceInfo.getResourceClass().getAnnotation(RolesAllowed.class);
        if (ra != null) {
            configuration.register(new RolesAllowedRequestFilter(
                Objects.requireNonNull(system, "@Permissions found on " + am + " but no @Authenticated found"),
                ra.value()));
        }
    }

    @Priority(Priorities.AUTHORIZATION + 120) // authorization filter - should go after any authentication filters
    private static class RolesAllowedRequestFilter implements ContainerRequestFilter {

        private final String system;
        private final boolean denyAll;
        private final String[] rolesAllowed;

        RolesAllowedRequestFilter(String system) {
            this.denyAll = true;
            this.rolesAllowed = null;
            this.system = system;
        }

        RolesAllowedRequestFilter(String system, String[] rolesAllowed) {
            this.system = system;
            this.denyAll = false;
            this.rolesAllowed = (rolesAllowed != null) ? rolesAllowed : new String[]{};
        }

        @Override
        public void filter(ContainerRequestContext request) throws IOException {
            Subject subject = SubjectContext.getSubject(system);
            LOGGER.trace("enter() {} - {}", subject, request.getUriInfo().getRequestUri());
            if (!denyAll) {
                for (String role : rolesAllowed) {
                    if (subject.hasRole(role)) {
                        return;
                    }
                }
            }
            throw new ForbiddenException();
        }
    }
}
