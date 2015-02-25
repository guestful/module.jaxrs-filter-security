package com.guestful.jaxrs.security.session;

/**
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public interface Expirable {

    int getMaxAge();

    long getLastAccessTime();

    default boolean isExpired() {
        return getTTL() == 0;
    }

    default int getTTL() {
        return Math.max(0, getMaxAge() - getLastAccessAge());
    }

    default int getLastAccessAge() {
        return Math.toIntExact((System.currentTimeMillis() - getLastAccessTime()) / 1000);
    }

}
