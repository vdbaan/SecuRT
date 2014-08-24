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

import java.sql.*;

/*
this is the proof of concept for annotating interface classes, in this case: java.sql.Statement. 
*/
public class SQLTest {

    @Test (expected = TaintException.class)
    public void testSQL() {
        String sql = "SELECT * FROM contacts WHERE name='"+getUserName()+"'";
        String createSQL = "create table contacts (name varchar(45),email varchar(45),phone varchar(45))";

        Connection connection;
        try {
            Class.forName("org.hsqldb.jdbcDriver");
            connection = DriverManager.getConnection("jdbc:hsqldb:mem:mymemdb", "SA", "");
            connection.createStatement().executeUpdate(createSQL);

            Statement statement = null;
            ResultSet resultSet = null;

            statement = connection.createStatement();
            // it should fail here :)
            resultSet = statement.executeQuery(sql);

            resultSet.close();
            statement.close();
            connection.close();
            fail("Should not get here");
        } catch (SQLException e) {
            System.err.println("Got an exception! ");
            System.err.println(e.getMessage());
            e.printStackTrace(System.err);
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    private String getUserName() {
        String userName = null;
        BufferedReader br = new BufferedReader(new StringReader("testing123"));
        try {
            userName = br.readLine();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return userName;
    }
}