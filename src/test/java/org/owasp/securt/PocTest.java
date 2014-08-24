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

import java.io.*;
import static org.junit.Assert.fail;
import org.junit.Test;

/*
this is the proof of concept that started it all. 
*/
public class PocTest {

	@Test (expected = TaintException.class)
	public void poc() {
		String userName = getUserName();

        System.out.println(userName);
        fail("TaintException should be thrown");
	}

	@Test (expected = TaintException.class)
	public void pocConcat() {
		String userName = getUserName();

        System.out.println("[SimpleTest] Hello: "+userName);
        fail("TaintException should be thrown");
	}

	@Test (expected = TaintException.class)
	public void pocFormat() {
		String userName = getUserName();

        System.out.println(String.format("[SimpleTest] Hello: %s",userName));
        fail("TaintException should be thrown");
	}

    @Test(expected = TaintException.class)
    public void pocFile() {
        try {
            FileInputStream fstream = new FileInputStream("src/test/resources/file.txt");
            DataInputStream in = new DataInputStream(fstream);
            BufferedReader br = new BufferedReader(new InputStreamReader(in));
            String strLine;

            while ((strLine = br.readLine()) != null) {
                System.out.println(strLine);
            }
            fail("TaintException should be thrown");
            //Close the input stream
            in.close();
        } catch (IOException ioe) {
            System.err.println("Error: " + ioe.getMessage());
        }
    }

    private String getUserName() {
		String userName = null;
		BufferedReader br = new BufferedReader(new StringReader("tainted String"));
        try {
            userName = br.readLine();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return userName;
	}
}
