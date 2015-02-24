package com.guestful.jaxrs.security.session;

/**
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public interface ConnectedSession extends Session {
    void invalidate();
}
