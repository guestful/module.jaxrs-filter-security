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

import com.guestful.jaxrs.security.subject.DelegatingSecurityContext;
import com.guestful.jaxrs.security.subject.DelegatingSubject;
import com.guestful.jaxrs.security.subject.Subject;
import com.guestful.jaxrs.security.subject.SubjectContext;

import javax.annotation.Priority;
import javax.inject.Inject;
import javax.inject.Provider;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.container.ContainerResponseFilter;
import java.io.IOException;
import java.util.logging.Logger;

/**
 * date 2014-05-23
 *
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
@Priority(Priorities.AUTHENTICATION + 120)
public class SubjectContextFilter implements ContainerRequestFilter, ContainerResponseFilter {

    private static final String BACKUP = SubjectContextFilter.class.getName() + ".SecurityContext.BACKUP";
    private static final Logger LOGGER = Logger.getLogger(SubjectContextFilter.class.getName());

    private final Provider<HttpServletRequest> rawRequest;

    @Inject
    public SubjectContextFilter(Provider<HttpServletRequest> rawRequest) {
        this.rawRequest = rawRequest;
    }

    @Override
    public void filter(ContainerRequestContext request) throws IOException {
        LOGGER.finest("enter() " + request.getSecurityContext().getUserPrincipal() + " - " + request.getUriInfo().getRequestUri());
        // install subject
        Subject subject = new DelegatingSubject(request);
        SubjectContext.setCurrentSubject(subject);
        // delegate security context calls to current subject
        if (request.getHeaderString("X-Forwarded-For") == null) {
            request.getHeaders().putSingle("X-Forwarded-For", rawRequest.get().getRemoteAddr());
        }
        request.setProperty(BACKUP, request.getSecurityContext());
        request.setSecurityContext(new DelegatingSecurityContext(request));
    }

    @Override
    public void filter(ContainerRequestContext request, ContainerResponseContext responseContext) throws IOException {
        LOGGER.finest("exit() " + request.getSecurityContext().getUserPrincipal() + " - " + request.getUriInfo().getRequestUri());
        // uninstall subject
        SubjectContext.clearCurrentSubject();
    }

}
