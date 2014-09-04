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
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.util.*;

/**
 * Created by steven on 18/08/14.
 */
public class SecurtModifier {

    static SecurtModifier instance = new SecurtModifier();

    public static final int ABSTRACTS = 1;
    public static final int INTERFACES = 2;
    public static final int CLASSES = 3;

    static Map<String, List<Definition>> interfaces, abstracts, classes;
    private static ClassPool classPool = null;

    public SecurtModifier() {
//        this(new FileInputStream("/home/steven/Projects/owasp/SecuRT/src/main/resources/securt.xml"));
//        this(Thread.currentThread().getContextClassLoader().getResource("securt.xml"));
        this(Thread.currentThread().getContextClassLoader().getResourceAsStream("securt.xml"));
    }

    public SecurtModifier(InputStream input) {
        interfaces = new HashMap<String, List<Definition>>();
        abstracts = new HashMap<String, List<Definition>>();
        classes = new HashMap<String, List<Definition>>();
        AbstractTaintUtil.info("Building modifier map");
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dBuilder = null;
        Document doc;
        try {
            if (input == null) {
                input = new FileInputStream("src/main/resources/securt.xml");
            }
            dBuilder = dbFactory.newDocumentBuilder();
            doc = dBuilder.parse(input);
            doc.getDocumentElement().normalize();
            parseInterfaces(doc);
            parseAbstracts(doc);
            parseClasses(doc);

        } catch (SAXException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
        }
        if ("true".equalsIgnoreCase(System.getProperty("LOG_EXCEPTIONS"))) {
            // start a shutdown hook that will log traces on shutdown
            AbstractTaintUtil.info("ShutdownHook activated");
            Runtime.getRuntime().addShutdownHook(new ShutdownHook());
        }
    }

    private void parseAbstracts(Document doc) {
        NodeList nList = doc.getElementsByTagName("abstract");
        parseNodeList(nList, ABSTRACTS);
    }

    private void parseInterfaces(Document doc) {
        NodeList nList = doc.getElementsByTagName("interface");
        parseNodeList(nList, INTERFACES);
    }

    private void parseClasses(Document doc) {
        NodeList nList = doc.getElementsByTagName("class");
        parseNodeList(nList, CLASSES);
    }

    private void parseNodeList(NodeList nList, int ia) {
        for (int i = 0; i < nList.getLength(); i++) {
            Node nNode = nList.item(i);
            if (nNode.getNodeType() == Node.ELEMENT_NODE) {
                Element eElement = (Element) nNode;
                String elemName = eElement.getAttribute("class");
                String elemType = eElement.getAttribute("type");
                String method = eElement.getAttribute("method");
                if ("".equals(method)) {
                    NodeList methods = eElement.getElementsByTagName("method");
                    for (int x = 0; x < methods.getLength(); x++) {
                        Node node = methods.item(x);
                        if (node.getNodeType() == Node.ELEMENT_NODE) {
                            Element element = (Element) node;
                            String name = element.getAttribute("name");
                            String args = element.getAttribute("arguments");
                            String vuln = element.getAttribute("vulnerable");

                            addSecurtElement(elemType, elemName, name, args, vuln, ia);
                        }
                    }
                } else {
                    String arguments = eElement.getAttribute("arguments");
                    String vuln = eElement.getAttribute("vulnerable");
                    addSecurtElement(elemType, elemName, method, arguments, vuln, ia);
                }
            }
        }
    }

    private void addSecurtElement(String type, String className, String methodName, String arguments, String vulnerable, int ia) {
        AbstractTaintUtil.debug("Adding element: " + className);
        AbstractTaintUtil.debug(">> type  : " + type);
        AbstractTaintUtil.debug(">> method: " + methodName);
        AbstractTaintUtil.debug(">> args  : " + arguments);
        AbstractTaintUtil.debug(">> vuln  : " + vulnerable);
        AbstractTaintUtil.debug(">> ia    : " + ia);
        switch (ia) {
            case INTERFACES:
                addDefinition(interfaces, className, new Definition(type, methodName, arguments, vulnerable));
                break;
            case ABSTRACTS:
                addDefinition(abstracts, className, new Definition(type, methodName, arguments, vulnerable));
                break;
            case CLASSES:
                addDefinition(classes, className, new Definition(type, methodName, arguments, vulnerable));
                break;
        }
    }


    private void addDefinition(Map<String, List<Definition>> map, String name, Definition definition) {
        List<Definition> l = map.get(name);
        if (l == null) {
            l = new ArrayList<Definition>();
        }
        l.add(definition);
        map.put(name, l);
    }

    public static byte[] translate(String className, ClassLoader loader, byte[] classfileBuffer)
            throws IOException, CannotCompileException {
        byte[] result = classfileBuffer;
        ClassPool cp = getClassPool();

        try {
            CtClass cc = cp.get(className);
            if (cc.isInterface())
                return result;

            if (classes.containsKey(cc.getName()))
                modify(classes, cc.getName(), cc);
            for (CtClass ctc : cc.getInterfaces()) {
                if (interfaces.containsKey(ctc.getName())) {
                    AbstractTaintUtil.debug("Will have to change this class: " + className);
                    modify(interfaces, ctc.getName(), cc);
                    result = cc.toBytecode();
                    AbstractTaintUtil.info("changed from " + classfileBuffer.length + " to " + result.length);
                }
            }
            CtClass object = cp.get("java.lang.Object");
            CtClass parent = cc;
            do {
                parent = parent.getSuperclass();
                if (abstracts.containsKey(parent.getName())) {
                    AbstractTaintUtil.debug("Will have to change this class: " + className);
                    modify(abstracts, parent.getName(), cc);
                }
            } while (parent != object);

            result = cc.toBytecode();
        } catch (NotFoundException e) {
            AbstractTaintUtil.debug(className + " is not in ClassPool");
        }

        return result;
    }

    private static void modify(Map<String, List<Definition>> map, String key, CtClass cc) throws CannotCompileException {
        for (Definition def : map.get(key)) {
            AbstractTaintUtil.debug("Changing: " + def);
            CtMethod m = null;
            try {
                m = cc.getDeclaredMethod(def.method, arguments(def.arguments));
                if ("source".equals(def.type)) {
                    sourceChange(m);
                } else {
                    sinkChange(m, Integer.parseInt(def.vulnerable));
                }
            } catch (NotFoundException e) {
                AbstractTaintUtil.debug(key + " doesn't contain: " + def);
//                e.printStackTrace();
            }

        }
    }

    private static void sourceChange(CtMethod method) throws NotFoundException, CannotCompileException {
        method.insertAfter("{if($_ != null) { $_.setTaint(true);$_.setTrace(java.lang.Thread.currentThread().getStackTrace());}}");
        AbstractTaintUtil.info("Added setTaint");
    }

    private static void sinkChange(CtMethod method, int vulnerable) throws NotFoundException, CannotCompileException {
        CtClass[] args = method.getParameterTypes();
        if (vulnerable > 0 && args.length >= vulnerable && args[vulnerable - 1].getName().equals("java.lang.String")) {
            method.insertBefore("{org.owasp.securt.TaintUtil.checkTaint($" + vulnerable + ");}");
            AbstractTaintUtil.info("Added checkTaint");
        }
    }

    private static ClassPool getClassPool() {
        if (classPool == null) {
            classPool = ClassPool.getDefault();
            classPool.appendClassPath(new LoaderClassPath(SecurtModifier.class.getClassLoader()));
            RuntimeMXBean mx = ManagementFactory.getRuntimeMXBean();
            try {
                addToClassPool(classPool, mx.getBootClassPath());
                addToClassPool(classPool, mx.getClassPath());

                classPool.appendPathList(System.getProperty("java.class.path"));
            } catch (NotFoundException e) {
                AbstractTaintUtil.error("java.class.path not found: " + e.getMessage());
                e.printStackTrace();
            }
        }
        return classPool;
    }

    private static void addToClassPool(ClassPool classPool, String path) throws NotFoundException {
        char sep = File.pathSeparatorChar;

        int i = 0;
        for (; ; ) {
            int j = path.indexOf(sep, i);
            if (j < 0) {
                AbstractTaintUtil.debug("adding to classpool: " + path.substring(i));
                if (new File(path.substring(i)).exists()) {
                    classPool.appendClassPath(path.substring(i));
                }
                break;
            } else {
                AbstractTaintUtil.debug("adding to classpool: " + path.substring(i, j));
                if (new File(path.substring(i, j)).exists()) {
                    classPool.appendClassPath(path.substring(i, j));
                }
                i = j + 1;
            }
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

    private static class ShutdownHook extends Thread {
        public void run() {
            System.out.println("printing");
        }
    }
}

class Definition {
    String type, method, arguments, vulnerable;

    public Definition(String elemType, String method, String arguments, String vuln) {
        this.type = elemType;
        this.method = method;
        this.arguments = arguments;
        this.vulnerable = vuln;
    }

    public String toString() {
        return String.format("Type: %s = [m:%s, a:%s, v:%s]", type, method, arguments, vulnerable);
    }
}