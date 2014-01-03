/*
Copyright (C) 2013 S. van der Baan

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>
*/
package org.owasp.securt;

import java.util.HashMap;

/**
 * Base class for simplifying tainting and checking taints.
 */
public abstract class AbstractTaintUtil {

    static {
        System.out.println("[*] Running static code here");
        Generator gen = new Generator();
        try {
            gen.processInterfaces();
        } catch(Exception e) {
            
        }
    }

    private static HashMap<String, Boolean> carrays = new HashMap<>();

    abstract void setTaint(String tainted, boolean taint);

    abstract void checkTaint(String tainted);

    public static void setTaint(char[] tainted, boolean taint) {
        carrays.put(new String(tainted), taint);
    }

    public static void checkTaint(char[] tainted) {
        if (carrays.get(tainted))
            markTaint();
    }

    protected static void markTaint() {
        System.out.println("[*] Throwing exception?"+System.getProperty("THROW_EXCEPTION"));
        if ("true".equalsIgnoreCase(System.getProperty("THROW_EXCEPTION")))
            throw new TaintException("Taint detected");
        else
            System.out.println("Taint detected");
    }
}
