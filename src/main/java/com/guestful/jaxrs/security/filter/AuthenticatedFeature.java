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
package com.guestful.jaxrs.security.filter;

import com.guestful.jaxrs.security.AuthenticationException;
import com.guestful.jaxrs.security.annotation.Authenticated;
import com.guestful.jaxrs.security.subject.SubjectSecurityContext;

import javax.annotation.Priority;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.DynamicFeature;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.FeatureContext;
import java.io.IOException;
import java.util.logging.Logger;

/**
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public class AuthenticatedFeature implements DynamicFeature {

    private static final Logger LOGGER = Logger.getLogger(AuthenticatedFilter.class.getName());

    @Override
    public void configure(ResourceInfo resourceInfo, FeatureContext context) {
        Authenticated authenticated = resourceInfo.getResourceMethod().getAnnotation(Authenticated.class);
        if (authenticated == null) {
            authenticated = resourceInfo.getResourceClass().getAnnotation(Authenticated.class);
        }
        if (authenticated != null) {
            context.register(new AuthenticatedFilter(authenticated));
        }
    }

    @Priority(Priorities.AUTHENTICATION + 123)
    public static class AuthenticatedFilter implements ContainerRequestFilter {

        private final Authenticated authenticated;

        public AuthenticatedFilter(Authenticated authenticated) {
            this.authenticated = authenticated;
        }

        @Override
        public void filter(ContainerRequestContext request) throws IOException {
            LOGGER.finest("enter() " + request.getSecurityContext().getUserPrincipal() + " - " + request.getUriInfo().getRequestUri());
            SubjectSecurityContext subjectSecurityContext = (SubjectSecurityContext) request.getSecurityContext();
            String system = authenticated.value();
            if (subjectSecurityContext.getUserPrincipal(system) == null) {
                throw new AuthenticationException("@Authenticated", authenticated.challenge(), request);
            }
        }

    }

}
