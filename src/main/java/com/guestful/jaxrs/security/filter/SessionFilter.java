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

import com.guestful.jaxrs.security.session.SessionConfigurations;
import com.guestful.jaxrs.security.subject.Subject;
import com.guestful.jaxrs.security.subject.SubjectSecurityContext;

import javax.annotation.Priority;
import javax.inject.Inject;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.container.ContainerResponseFilter;
import java.io.IOException;
import java.util.logging.Logger;

/**
 * date 2014-05-23
 *
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
@Priority(Priorities.AUTHORIZATION + 122)
public class SessionFilter implements ContainerResponseFilter {

    private static final Logger LOGGER = Logger.getLogger(SessionFilter.class.getName());

    private final SessionConfigurations sessionConfigurations;

    @Inject
    public SessionFilter(SessionConfigurations sessionConfigurations) {
        this.sessionConfigurations = sessionConfigurations;
    }

    @Override
    public void filter(ContainerRequestContext request, ContainerResponseContext response) throws IOException {
        SubjectSecurityContext subjectSecurityContext = (SubjectSecurityContext) request.getSecurityContext();
        sessionConfigurations.forEach((system, config) -> {
            Subject subject = subjectSecurityContext.getSubject(system);
            LOGGER.finest("exit() " + subjectSecurityContext.getUserPrincipal(system) + " - " + request.getUriInfo().getRequestUri() + " - save session " + subject.getSession().getId());
            subject.accessed();
        });
    }

}
