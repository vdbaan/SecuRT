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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;
import org.junit.Test;
import java.lang.reflect.*;

public class SecuRTest {

	@Test
	public void testTaintedString() {
		// test if String containts the taint
		try  {
			Class string = Class.forName("java.lang.String");
			Field field = string.getDeclaredField("tainted");
			assertNotNull("Taint field is present",field);
		} catch(Exception e) {
			fail("Problem in the basement: "+e.toString());
		}
	}
}