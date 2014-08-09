package org.owasp.securt;

import org.apache.jasper.servlet.JspServlet;
import org.apache.servlet.textInput;
import org.junit.After;
import org.mortbay.jetty.testing.HttpTester;
import org.mortbay.jetty.testing.ServletTester;

import org.junit.Before;
import org.junit.Test;
import static junit.framework.TestCase.assertEquals;
import static org.junit.Assert.assertTrue;


/**
 * Created by steven on 05/08/14.
 */
public class HelloWorldJspTest {
    ServletTester tester = new ServletTester();
    HttpTester request = new HttpTester();
    HttpTester response = new HttpTester();

    @Before
    public void setUp() {
        tester.setResourceBase("./src/main/webapp/jsp");
        tester.addServlet(JspServlet.class, "*.jsp");
        tester.addServlet(textInput.class,"/servlet/*");
        try {
            tester.start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

//    @Test
    public void testHelloWorld() {
        request.setMethod("GET");
        request.setVersion("HTTP/1.0");
        request.setURI("/hello-world.jsp");
        try {
            response.parse(tester.getResponses(request.generate()));

            assertTrue(response.getMethod() == null);
            assertEquals(200, response.getStatus());
            assertEquals("<html><body>Hello World</body></html>", response.getContent());
        } catch (Exception e) {
            e.printStackTrace();
        }
        // JSP is compiled
    }

//    @Test
    public void testName() {
        request.setMethod("GET");
        request.setVersion("HTTP/1.0");
        request.setURI("/textInput.jsp?yourName=my+name");
        try {
            response.parse(tester.getResponses(request.generate()));

            assertTrue(response.getMethod() == null);
            assertEquals(200, response.getStatus());
            assertEquals("<html><body>Hello World</body></html>", response.getContent());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    public void testServlet() {
        request.setMethod("GET");
        request.setVersion("HTTP/1.0");
        request.setURI("/servlet/?yourName=my+servlet");
        try {
            response.parse(tester.getResponses(request.generate()));

            assertTrue(response.getMethod() == null);
            assertEquals(200, response.getStatus());
            assertEquals("<html><body>Hello World</body></html>", response.getContent());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    @After
    public void done() {
        try {
            tester.stop();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
