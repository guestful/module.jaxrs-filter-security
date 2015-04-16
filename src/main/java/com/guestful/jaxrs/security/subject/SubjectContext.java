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

import com.guestful.jaxrs.security.SecurityService;
import com.guestful.jaxrs.security.session.ConnectedSession;
import com.guestful.jaxrs.security.token.AuthenticationToken;

import javax.security.auth.login.LoginException;
import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;

/**
 * date 2014-05-23
 *
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public class SubjectContext {

    private static SecurityService SERVICE;

    private static SecurityService getSecurityService() {
        if (SERVICE == null) {
            throw new IllegalStateException("No " + SecurityService.class.getSimpleName() + " set");
        }
        return SERVICE;
    }

    private static final ThreadLocal<Map<String, Subject>> SUBJECTS = new ThreadLocal<Map<String, Subject>>() {
        @Override
        protected Map<String, Subject> initialValue() {
            return new ConcurrentHashMap<>();
        }
    };

    static void logout(Subject subject) {
        if (subject == null) throw new NullPointerException();
        getSecurityService().logout(subject);
        SUBJECTS.get().remove(subject.getSystem(), subject);
    }

    static Stream<ConnectedSession> getConnectedSessions(Subject subject) {
        if (subject.getPrincipal() != null && subject.getSession(false) != null && subject.getAuthenticationToken() != null) {
            return getSecurityService().getConnectedSessions(subject.getSystem(), subject.getPrincipal());
        }
        return Stream.empty();
    }

    // PUBLIC

    public static void setSecurityService(SecurityService securityService) {
        if (SERVICE != null) {
            throw new IllegalStateException(SecurityService.class.getSimpleName() + " already set");
        }
        SERVICE = securityService;
    }

    public static Subject login(AuthenticationToken token) throws LoginException {
        if (token == null) throw new NullPointerException();
        Subject current = getSubject(token.getSystem(), false);
        if (current == null) {
            throw new IllegalStateException("No login context found");
        }
        Subject subject = getSecurityService().login(token, current);
        setCurrentSubject(subject);
        return subject;
    }

    public static Collection<Subject> getSubjects() {
        return SUBJECTS.get().values();
    }

    public static Subject getSubject() {
        return getSubject("", true);
    }

    public static Subject getSubject(String system) {
        return getSubject(system, true);
    }

    public static Subject getSubject(boolean createAnonymousIfNone) {
        return getSubject("", createAnonymousIfNone);
    }

    public static Subject getSubject(String system, boolean createAnonymousIfNone) {
        Map<String, Subject> subjects = SUBJECTS.get();
        Subject subject = subjects.get(system);
        if (subject == null && createAnonymousIfNone) {
            subject = new AnonymousSubject(system);
        }
        return subject;
    }

    public static void setCurrentSubject(Subject subject) {
        if (subject == null) throw new NullPointerException();
        if (subject instanceof AnonymousSubject) throw new IllegalArgumentException();
        SUBJECTS.get().put(subject.getSystem(), subject);
    }

    public static void clear() {
        SUBJECTS.remove();
    }

    public static void accessed(Subject subject) {
        if (subject == null) throw new NullPointerException();
        getSecurityService().accessed(subject);
    }

}
