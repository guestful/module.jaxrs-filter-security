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
package com.guestful.jaxrs.security.util;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.junit.Assert.assertEquals;

/**
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
@RunWith(JUnit4.class)
public final class CryptoTest {

    @Test
    public void test_hash() throws Exception {
        String hash = "fc8c23dbea1a08b13c0c872e23dc868ae79fececf8eb25569e0c46d557b80a5754bf9de5eef75bf8bc8001f4fa59f4746decdbeee8e24b8ce79eef1782eafe2d";
        assertEquals(hash, Crypto.sha512("password1", "okoMskkfJxo9JcOzF7Bpiw", 3));
    }

}
