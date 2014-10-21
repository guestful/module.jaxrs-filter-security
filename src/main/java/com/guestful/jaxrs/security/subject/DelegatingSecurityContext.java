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

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.SecurityContext;

/**
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public class DelegatingSecurityContext implements SubjectSecurityContext {

    private final SecurityContext previousSecurityContext;
    private final ContainerRequestContext request;

    public DelegatingSecurityContext(ContainerRequestContext request) {
        this.request = request;
        this.previousSecurityContext = request.getSecurityContext();
    }

    @Override
    public boolean isSecure() {
        return previousSecurityContext.isSecure() || "https".equalsIgnoreCase(request.getHeaderString("X-Forwarded-Proto"));
    }

}
