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

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;

/**
 * Base class for simplifying tainting and checking taints.
 */
public abstract class AbstractTaintUtil {

    private static boolean throwException = "true".equalsIgnoreCase(System.getProperty("THROW_EXCEPTION"));
    private static boolean logExceptions = "true".equalsIgnoreCase(System.getProperty("LOG_EXCEPTIONS"));
    private static boolean logquiet = "quiet".equalsIgnoreCase(System.getProperty("SECURT_LOGLEVEL"));
    private static boolean logwarn = "warn".equalsIgnoreCase(System.getProperty("SECURT_LOGLEVEL"));
    private static boolean loginfo = "info".equalsIgnoreCase(System.getProperty("SECURT_LOGLEVEL"));
    private static boolean logdebug = "debug".equalsIgnoreCase(System.getProperty("SECURT_LOGLEVEL"));
    private static DateFormat formatter = new SimpleDateFormat("HH:mm:ss:SSS");

    private static HashMap<StackTraceElement[],String > traces = new HashMap<>();

    private static HashMap<String, Boolean> carrays = new HashMap<>();

    abstract void setTaint(String tainted, boolean taint);

    abstract void checkTaint(String tainted);

    abstract void printTrace(String tainted);

    public static void setTaint(char[] tainted, boolean taint) {
        carrays.put(new String(tainted), taint);
    }

    public static void checkTaint(char[] tainted) {
        if (carrays.get(tainted))
            markTaint(null);
    }

    public static HashMap<StackTraceElement[], String> getTraces() {
        return traces;
    }

    protected static void markTaint(String taintedString) {
        System.out.println("[*] Throwing exception?" + throwException);
        if(logExceptions) {
            traces.put(java.lang.Thread.currentThread().getStackTrace(),taintedString);
        }else if (throwException)
            throw new TaintException("Taint detected");
        else
            System.out.println("Taint detected");
    }

    public static void error(String message) {
        log("ERROR", message);
    }

    public static void warn(String message) {
        if (logwarn || loginfo || logdebug)
            log(" warn", message);
    }

    public static void info(String message) {
        if (loginfo || logdebug) {
            log(" info", message);
        }
    }

    public static void debug(String message) {
        if (logdebug) {
            log("debug", message);
        }

    }

    private static void log(String level, String message) {
        if (!logquiet) {
            final long timestamp = new Date().getTime();
            String c = Thread.currentThread().getStackTrace()[3].getClassName();
            String m = Thread.currentThread().getStackTrace()[3].getMethodName();
            System.err.println(String.format("%s [%s] (%s.%s): %s", formatter.format(timestamp), level, c, m, message));
            System.err.flush();
        }
    }
}
