/*
Copyright (C) 2013 S. van der Baan

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/
package org.owasp.securt;

/**
 * Created by steven on 05/10/14.
 */
public class Taint {
    public enum TaintType {SOURCE, SINK, CHECK, TRANSITION}

    private Taint[] leafs;
    StackTraceElement[] trace;
    TaintType type;

    public static Taint newSource() {
        return newSource(0);
    }

    public static Taint newSource(int depth) {
        return newTaint(depth, TaintType.SOURCE);
    }

    public static Taint newTaint(int depth, TaintType type) {
        Taint result = new Taint();
        result.setType(type);
        result.setTrace(java.lang.Thread.currentThread().getStackTrace());
        return result;
    }

    public Taint[] getLeafs() {
        return leafs;
    }

    public void setLeafs(Taint[] leafs) {
        this.leafs = leafs;
    }

    public StackTraceElement[] getTrace() {
        return trace;
    }

    public void setTrace(StackTraceElement[] trace) {
        this.trace = trace;
    }

    public TaintType getType() {
        return type;
    }

    public void setType(TaintType type) {
        this.type = type;
    }
}