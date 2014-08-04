/*
Copyright (C) 2014 S. van der Baan

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

import javassist.*;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.IOException;
import java.lang.management.*;
import java.util.*;

/**
 * Created by steven on 07/01/14.
 */
public class InterfaceModifier {
    Document doc;

    public InterfaceModifier() {

//        this(Thread.currentThread().getContextClassLoader().getResource("securt.xml").getFile());
        this("/home/steven/Projects/owasp/SecuRT/src/main/resources/securt.xml");
    }

    static Map<String, List<Interface>> interfaces = new HashMap<String, List<Interface>>();

    public InterfaceModifier(String xmlFile) {
        AbstractTaintUtil.info("Building interfaces map");
        String orig = System.setProperty("java.security.manager", "org.owasp.securt.SecurityManager");
        AbstractTaintUtil.debug("Set security mgr from: " + orig);
        AbstractTaintUtil.debug(" to: " + System.getProperty("java.security.manager"));

        File fXmlFile = new File(xmlFile);
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dBuilder = null;
        try {
            dBuilder = dbFactory.newDocumentBuilder();
            doc = dBuilder.parse(fXmlFile);
            doc.getDocumentElement().normalize();
            NodeList nList = doc.getElementsByTagName("interface");
            for (int i = 0; i < nList.getLength(); i++) {
                Node nNode = nList.item(i);
                if (nNode.getNodeType() == Node.ELEMENT_NODE) {
                    Element eElement = (Element) nNode;
                    String elemName = eElement.getAttribute("class");
                    String elemType = eElement.getAttribute("type");
                    String method = eElement.getAttribute("method");
                    String arguments = eElement.getAttribute("arguments");
                    String vuln = eElement.getAttribute("vulnerable");
                    AbstractTaintUtil.debug("Adding interface: " + elemName);
                    AbstractTaintUtil.debug(">> type  : " + elemType);
                    AbstractTaintUtil.debug(">> method: " + method);
                    AbstractTaintUtil.debug(">> args  : " + arguments);
                    AbstractTaintUtil.debug(">> vuln  : " + vuln);
                    addInterface(elemName, new Interface(elemType, method, arguments, vuln));
                }
            }
            AbstractTaintUtil.debug("interfaces size: " + interfaces.size());
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
        } catch (SAXException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        if("true".equalsIgnoreCase(System.getProperty("LOG_EXCEPTIONS"))) {
            // start a shutdown hook that will log traces on shutdown
            Runtime.getRuntime().addShutdownHook(new ShutdownHook());
        }
    }

    private static class ShutdownHook extends Thread {
        public void run() {

        }
    }
    private void addInterface(String name, Interface interf) {
        List<Interface> l = interfaces.get(name);
        if (l == null) {
            l = new ArrayList<Interface>();
        }
        l.add(interf);
        interfaces.put(name, l);
    }

    static InterfaceModifier instance = new InterfaceModifier();

    private static ClassPool classPool = null;

    private static void addToClassPool(ClassPool classPool, String path) throws NotFoundException {
        char sep = File.pathSeparatorChar;

        int i = 0;
        for (; ; ) {
            int j = path.indexOf(sep, i);
            if (j < 0) {
                AbstractTaintUtil.debug("adding to classpool: "+path.substring(i));
                if (new File(path.substring(i)).exists()) {
                    classPool.appendClassPath(path.substring(i));
                }
                break;
            } else {
                AbstractTaintUtil.debug("adding to classpool: "+path.substring(i,j));
                if (new File(path.substring(i, j)).exists()) {
                    classPool.appendClassPath(path.substring(i, j));
                }
                i = j + 1;
            }
        }

    }
    private static ClassPool getClassPool() {
        if (classPool == null) {
            classPool = ClassPool.getDefault();
            classPool.appendClassPath(new LoaderClassPath(InterfaceModifier.class.getClassLoader()));
            RuntimeMXBean mx = ManagementFactory.getRuntimeMXBean();
            try {
                addToClassPool(classPool,mx.getBootClassPath());
                addToClassPool(classPool,mx.getClassPath());

                classPool.appendPathList(System.getProperty("java.class.path"));
            } catch (NotFoundException e) {
                AbstractTaintUtil.error("java.class.path not found: " + e.getMessage());
                e.printStackTrace();
            }
        }
        return classPool;
    }

    public static byte[] translate(String className, ClassLoader loader, byte[] classfileBuffer) throws IOException, CannotCompileException, NotFoundException {
//        org.owasp.securt.AbstractTaintUtil.debug("Checking class: " + className);
        byte[] result = classfileBuffer;
        try {
            ClassPool cp = getClassPool();

            CtClass cc = cp.get(className);
//            AbstractTaintUtil.info("step");
            for (CtClass ctc : cc.getInterfaces()) {
                if (interfaces.containsKey(ctc.getName())) {
                    AbstractTaintUtil.debug("Will have to change this class: " + className);
                    for (Interface intf : interfaces.get(ctc.getName())) {
                        AbstractTaintUtil.debug("Changing: " + intf);
                        CtMethod m = cc.getDeclaredMethod(intf.method, arguments(intf.arguments));
                        sinkChange(m, Integer.parseInt(intf.vulnerable));
                    }
                    result = cc.toBytecode();
                    AbstractTaintUtil.info("changed from " + classfileBuffer.length + " to " + result.length);
                }
            }

        } catch (NotFoundException nfe) {
            AbstractTaintUtil.warn("class not found: " + nfe);
            nfe.printStackTrace();
//            throw nfe;
            result = null;
        }
        return result;
    }

    private static void showImportedPackages(ClassPool cp) {
        for (Iterator i = cp.getImportedPackages(); i.hasNext(); ) {
            AbstractTaintUtil.info("Imported: " + i.next());
        }
    }


    private CtClass buildSink(Element element, String clazz, String method, String arguments, int vulnerable) throws NotFoundException, CannotCompileException, IOException {
        ClassPool cp = ClassPool.getDefault();
        CtClass cc = cp.get(clazz);
        if ("".equals(method)) {
            NodeList methods = element.getElementsByTagName("method");
            for (int i = 0; i < methods.getLength(); i++) {
                Node nNode = methods.item(i);
                if (nNode.getNodeType() == Node.ELEMENT_NODE) {
                    Element eElement = (Element) nNode;
                    String name = eElement.getAttribute("name");
                    String args = eElement.getAttribute("arguments");
                    CtMethod m = cc.getDeclaredMethod(name, arguments(args));
                    sinkChange(m, vulnerable);
                }
            }
        } else {
            CtMethod m = cc.getDeclaredMethod(method, arguments(arguments));
            sinkChange(m, vulnerable);
        }
        return cc;
    }

    private static void sinkChange(CtMethod method, int vulnerable) throws NotFoundException, CannotCompileException {
        CtClass[] args = method.getParameterTypes();
        if (vulnerable > 0 && args.length >= vulnerable && args[vulnerable - 1].getName().equals("java.lang.String")) {
            method.insertBefore("{org.owasp.securt.TaintUtil.checkTaint($" + vulnerable + ");}");
            AbstractTaintUtil.info("Added checkTaint");
        }
    }


    private static CtClass[] arguments(String arguments) throws NotFoundException {
        StringTokenizer st = new StringTokenizer(arguments, ",");
        CtClass[] result = new CtClass[st.countTokens()];
        int counter = 0;
        while (st.hasMoreTokens()) {
            String token = st.nextToken();
            if ("boolean".equalsIgnoreCase(token))
                result[counter++] = CtClass.booleanType;
            else if ("byte".equalsIgnoreCase(token))
                result[counter++] = CtClass.byteType;
            else if ("char".equalsIgnoreCase(token))
                result[counter++] = CtClass.charType;
            else if ("double".equalsIgnoreCase(token))
                result[counter++] = CtClass.doubleType;
            else if ("float".equalsIgnoreCase(token))
                result[counter++] = CtClass.floatType;
            else if ("int".equalsIgnoreCase(token))
                result[counter++] = CtClass.intType;
            else if ("long".equalsIgnoreCase(token))
                result[counter++] = CtClass.longType;
            else if ("short".equalsIgnoreCase(token))
                result[counter++] = CtClass.shortType;
            else if ("void".equalsIgnoreCase(token))
                result[counter++] = CtClass.voidType;
            else {
                ClassPool cp = ClassPool.getDefault();
                result[counter++] = cp.get(token);
            }
        }

        return result;
    }
}

class Interface {
    String type, method, arguments, vulnerable;

    public Interface(String elemType, String method, String arguments, String vuln) {
        this.type = elemType;
        this.method = method;
        this.arguments = arguments;
        this.vulnerable = vuln;
    }

    public String toString() {
        return String.format("Type: %s = [m:%s, a:%s, v:%s]", type, method, arguments, vulnerable);
    }
}
