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

import com.guestful.jaxrs.security.AuthenticationException;
import com.guestful.jaxrs.security.annotation.Authenticated;
import com.guestful.jaxrs.security.annotation.Permissions;
import com.guestful.jaxrs.security.subject.Subject;
import com.guestful.jaxrs.security.subject.SubjectContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Priority;
import javax.ws.rs.ForbiddenException;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.DynamicFeature;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.FeatureContext;
import java.io.IOException;
import java.lang.reflect.Method;
import java.util.*;

/**
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public class PermissionsFeature implements DynamicFeature {

    private static final Logger LOGGER = LoggerFactory.getLogger(PermissionFilter.class);

    @Override
    public void configure(ResourceInfo resourceInfo, FeatureContext context) {
        Method am = resourceInfo.getResourceMethod();
        if (am.isAnnotationPresent(Permissions.class)) {
            Authenticated authenticated = am.getAnnotation(Authenticated.class);
            if (authenticated == null) {
                authenticated = resourceInfo.getResourceClass().getAnnotation(Authenticated.class);
                if (authenticated == null) {
                    throw new IllegalStateException("@Permissions found on " + am + " but no @Authenticated found");
                }
            }
            List<String> permissions = Arrays.asList(am.getAnnotation(Permissions.class).value());
            Collection<String> vars = new HashSet<>();
            for (String p : permissions) {
                int s = p.indexOf('{');
                while (s != -1) {
                    int e = p.indexOf('}', s + 1);
                    vars.add(p.substring(s + 1, e));
                    s = p.indexOf('{', e + 1);
                }
            }
            context.register(new PermissionFilter(authenticated.value(), permissions, vars));
        }
    }

    @Priority(Priorities.AUTHORIZATION + 121)
    public static class PermissionFilter implements ContainerRequestFilter {

        private final Collection<String> permissions;
        private final Collection<String> vars;
        private final String system;

        PermissionFilter(String system, Collection<String> permissions, Collection<String> vars) {
            this.permissions = permissions;
            this.vars = vars;
            this.system = system;
        }

        @Override
        public void filter(ContainerRequestContext request) throws IOException {
            Subject subject = SubjectContext.getSubject(system);
            LOGGER.trace("enter() {} - {}", subject, request.getUriInfo().getRequestUri());
            if (subject.getPrincipal() == null) {
                throw new AuthenticationException("@Permissions", request);
            }
            Map<String, String> ctx = new LinkedHashMap<>();
            for (String var : vars) {
                String val = request.getUriInfo().getPathParameters().getFirst(var);
                ctx.put(var, val == null ? "" : val);
            }
            Collection<String> resolved = new HashSet<>();
            for (String permission : permissions) {
                for (Map.Entry<String, String> entry : ctx.entrySet()) {
                    permission = permission.replace('{' + entry.getKey() + '}', entry.getValue());
                }
                resolved.add(permission);
            }
            if (!subject.isPermitted(resolved)) {
                throw new ForbiddenException("Invalid permissions");
            }
        }
    }

}
