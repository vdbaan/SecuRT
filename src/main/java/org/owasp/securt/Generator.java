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

import javassist.*;
import org.apache.commons.cli.*;
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
import java.util.StringTokenizer;

/**
 * Used to generate the bootstrap classes and the source-sink classes.
 */
public class Generator {
    public static void main(String[] args) {

        Options options = new Options();
        Option d = new Option("d", "destination", true, "Sets destination directory");
        d.setRequired(true);
        Option s = new Option("s", "source", true, "The source XML");
        Option p = new Option("p", "prepare", false, "Prepares the bootstrap");
        options.addOption(d);
        options.addOption(s);
        options.addOption(p);

        Generator g = new Generator();

        CommandLineParser parser = new BasicParser();
        try {
            CommandLine cmd = parser.parse(options, args);
            String destPath = cmd.getOptionValue("d");

            if (cmd.hasOption('p')) {
                g.createString(destPath);
                g.changeStringBuilder(destPath);
                g.createTaintUtil(destPath);
                g.changeClassLoader(destPath);
                g.modifyShutdownHook(destPath);
            } else {
                String source = cmd.getOptionValue("s");
                g.parseXmlFile(destPath, source);
            }

        } catch (MissingOptionException e) {
            HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp(Generator.class.getCanonicalName(), options);
        } catch (ParseException e) {
            e.printStackTrace();
        } catch (NotFoundException e) {
            e.printStackTrace();
        } catch (CannotCompileException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
        } catch (SAXException e) {
            e.printStackTrace();
        }
    }

    private void modifyShutdownHook(String destPath)  throws NotFoundException, CannotCompileException, IOException {
        ClassPool cp = ClassPool.getDefault();
        CtClass cc = cp.getCtClass("org.owasp.securt.InterfaceModifier$ShutdownHook");
        CtMethod m = cc.getDeclaredMethod("run");
        m.setBody("{java.util.Iterator it = org.owasp.securt.AbstractTaintUtil.getTraces().entrySet().iterator();" +
                  " while(it.hasNext()) {" +
                  "   java.util.Map.Entry pair = (java.util.Map.Entry)it.next();"+
                  "   System.out.println(\"Trace started at:\"+((String)pair.getValue()).getTrace());" +
                  "   System.out.println(\"exiting at:\"+pair.getKey());" +
                  "   it.remove();" +
                  "}}");
        cc.writeFile(destPath);
        org.owasp.securt.AbstractTaintUtil.debug("Adapted: "+cc.getName());
    }


    private void createString(String destPath) throws NotFoundException, CannotCompileException, IOException {
        ClassPool cp = ClassPool.getDefault();
        CtClass cc = cp.get("java.lang.String");
        CtField f = new CtField(CtClass.booleanType, "tainted", cc);
        f.setModifiers(Modifier.PRIVATE);
        cc.addField(f);
        cc.addMethod(CtNewMethod.getter("isTainted", f));
        cc.addMethod(CtNewMethod.setter("setTaint", f));
        CtField trace = CtField.make("private StackTraceElement[] trace;",cc);
        cc.addField(trace);
        cc.addMethod(CtNewMethod.getter("getTrace",trace));
        cc.addMethod(CtNewMethod.setter("setTrace", trace));
        cc.writeFile(destPath);
        org.owasp.securt.AbstractTaintUtil.debug("Adapted: "+cc.getName());
    }

    private void changeStringBuilder(String destPath) throws NotFoundException, CannotCompileException, IOException {
        ClassPool cp = ClassPool.getDefault();
        CtClass cc = cp.get("java.lang.AbstractStringBuilder");
        CtField f = new CtField(CtClass.booleanType, "tainted", cc);
        f.setModifiers(Modifier.PROTECTED);
        cc.addField(f);
        CtMethod m = cc.getDeclaredMethod("append", new CtClass[]{cp.get("java.lang.String")});
        m.insertAfter("{$0.tainted |= ($1).isTainted();}");
        cc.writeFile(destPath);

        cc = cp.get("java.lang.StringBuilder");
        m = cc.getDeclaredMethod("toString");
        // $_.setTrace(java.lang.Thread.currentThread().getStackTrace());
        m.insertAfter("{$_.setTaint(tainted);$_.setTrace(java.lang.Thread.currentThread().getStackTrace());}");
        cc.writeFile(destPath);
        org.owasp.securt.AbstractTaintUtil.debug("Adapted: "+cc.getName());
    }

    private static void createTaintUtil(String destPath) throws NotFoundException, CannotCompileException, IOException {

        ClassPool cp = ClassPool.getDefault();

        // Just a shortcut to copy the Superclass to the new destination
        CtClass atu = cp.get("org.owasp.securt.AbstractTaintUtil");
        atu.writeFile(destPath);

        CtClass cc = cp.makeClass("org.owasp.securt.TaintUtil", atu);

        cc.addMethod(CtNewMethod.make("public static void setTaint(String tainted, boolean taint) {if(tainted != null){tainted.setTaint(taint);tainted.setTrace(java.lang.Thread.currentThread().getStackTrace());}}", cc));
        cc.addMethod(CtNewMethod.make("public static void checkTaint(String tainted) {if(tainted.isTainted())markTaint(tainted);}", cc));
//        cc.addMethod(CtNewMethod.make("public static void ",cc));

        org.owasp.securt.AbstractTaintUtil.debug("Created: " + cc.getName());
        cc.writeFile(destPath);
    }

    private void parseXmlFile(String destPath, String xmlFile) throws ParserConfigurationException, IOException, SAXException, NotFoundException, CannotCompileException {
        File fXmlFile = new File(xmlFile);
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
        Document doc = dBuilder.parse(fXmlFile);

        doc.getDocumentElement().normalize();

        processDoc(destPath, doc, "source");
        processDoc(destPath, doc, "sink");
    }

    private void processDoc(String destPath, Document doc, String type) throws NotFoundException, CannotCompileException, IOException {
        NodeList nList = doc.getElementsByTagName(type);
        org.owasp.securt.AbstractTaintUtil.debug(String.format("Processing %d elements of type %s", nList.getLength(), type));
        for (int i = 0; i < nList.getLength(); i++) {
            Node nNode = nList.item(i);
            if (nNode.getNodeType() == Node.ELEMENT_NODE) {
                Element eElement = (Element) nNode;
                String clazz = eElement.getAttribute("class");
                String method = eElement.getAttribute("method");
                String arguments = eElement.getAttribute("arguments");
                String vuln = eElement.getAttribute("vulnerable");
                int vulnerable = -1;
                if (vuln != null && !vuln.equals("")) {
                    vulnerable = Integer.parseInt(vuln);

                }
                if ("source".equals(type))
                    buildSource(destPath, eElement, clazz, method, arguments);
                else if ("sink".equals(type))
                    buildSink(destPath, eElement, clazz, method, arguments, vulnerable);
            }
        }
    }

    private void buildSink(String destPath, Element element, String clazz, String method, String arguments, int vulnerable) throws NotFoundException, CannotCompileException, IOException {
        ClassPool cp = ClassPool.getDefault();
        CtClass cc = cp.get(clazz);
        org.owasp.securt.AbstractTaintUtil.debug(String.format("Building sink for class: %s", clazz));
        boolean write = false;
        if ("".equals(method)) {
            NodeList methods = element.getElementsByTagName("method");
            for (int i = 0; i < methods.getLength(); i++) {
                Node nNode = methods.item(i);
                if (nNode.getNodeType() == Node.ELEMENT_NODE) {
                    Element eElement = (Element) nNode;
                    String name = eElement.getAttribute("name");
                    String args = eElement.getAttribute("arguments");
                    CtMethod m = cc.getDeclaredMethod(name, arguments(args));
                    String vuln = eElement.getAttribute("vulnerable");

                    if (vuln != null && !vuln.equals("")) {
                        vulnerable = Integer.parseInt(vuln);

                    }
                    write = sinkChange(m, vulnerable);
                }
            }
        } else {
            CtMethod m = cc.getDeclaredMethod(method, arguments(arguments));
            write = sinkChange(m, vulnerable);
        }
        if (write && destPath != null)
            cc.writeFile(destPath);
    }

    private boolean sinkChange(CtMethod method, int vulnerable) throws NotFoundException, CannotCompileException {
        boolean result = false;
        CtClass[] args = method.getParameterTypes();
        if (vulnerable > 0 && args.length >= vulnerable && args[vulnerable - 1].getName().equals("java.lang.String")) {
            org.owasp.securt.AbstractTaintUtil.debug(String.format("    modified method: %s", method.getName()));
            method.insertBefore("{org.owasp.securt.TaintUtil.checkTaint($" + vulnerable + ");}");
            result = true;
        } else {
            System.err.println(String.format("[E] %s does not take a String, but %s", method.getLongName(),args[vulnerable-1]));
        }

        return result;
    }

    private void buildSource(String destPath, Element element, String clazz, String method, String arguments) throws NotFoundException, CannotCompileException, IOException {
        ClassPool cp = ClassPool.getDefault();
        CtClass cc = cp.get(clazz);
        boolean write = false;
        org.owasp.securt.AbstractTaintUtil.debug(String.format("Building source for class: %s", clazz));
        if ("".equals(method)) {
            NodeList methods = element.getElementsByTagName("method");
            for (int i = 0; i < methods.getLength(); i++) {
                Node nNode = methods.item(i);
                if (nNode.getNodeType() == Node.ELEMENT_NODE) {
                    Element eElement = (Element) nNode;
                    String name = eElement.getAttribute("name");
                    String args = eElement.getAttribute("arguments");
                    CtMethod m = cc.getDeclaredMethod(name, arguments(args));
                    write = sourceChange(m);
                }
            }
        } else {
            CtMethod m = cc.getDeclaredMethod(method, arguments(arguments));
            write = sourceChange(m);
        }
        if (write)
            cc.writeFile(destPath);
    }

    private boolean sourceChange(CtMethod method) throws NotFoundException, CannotCompileException {
        boolean result = false;
        if (method.getReturnType().getName().equals("java.lang.String")) {
            org.owasp.securt.AbstractTaintUtil.debug(String.format("    modified method: %s", method.getName()));
            method.insertAfter("{if($_ != null) { $_.setTaint(true);$_.setTrace(java.lang.Thread.currentThread().getStackTrace());}}");
            result = true;
        } else {
            System.err.println(String.format("[E] %s does not return a String", method.getLongName()));
        }
        return result;
    }

    private CtClass[] arguments(String arguments) throws NotFoundException {
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

    private void changeClassLoader(String destPath) throws NotFoundException, CannotCompileException, IOException {
        ClassPool cp = ClassPool.getDefault();
        CtClass cc = cp.get("java.lang.ClassLoader");
        for (CtMethod method : cc.getDeclaredMethods()) {
            if (method.getName().equals("defineClass")) {
                if (method.getParameterTypes().length == 5
                        && method.getParameterTypes()[1].isArray()) {
                    wrapMethod(cc, method);
                }
            }
        }
        CtMethod m = cc.getDeclaredMethod("defineClass", arguments("java.lang.String,java.nio.ByteBuffer,java.security.ProtectionDomain"));
        m.setName("wrappedDefineClass");
        cc.addMethod(CtMethod.make(
                "protected final Class defineClass(String name, java.nio.ByteBuffer b,java.security.ProtectionDomain protectionDomain) {"
//                        + " org.owasp.securt.AbstractTaintUtil.info(\"finding wrapper for:\"+name);"
                        + " return wrappedDefineClass(name,b,protectionDomain);"
                        + "}",
                cc
        ));
        cc.writeFile(destPath);
        org.owasp.securt.AbstractTaintUtil.debug("Adapted: " + cc.getName());
    }

    private void wrapMethod(CtClass clazz, CtMethod method) throws NotFoundException, CannotCompileException {
        method.setName("wrappedDefineClass");
        CtMethod wrapper = CtNewMethod.make(Modifier.PROTECTED, method.getReturnType(), "defineClass", method.getParameterTypes(), method.getExceptionTypes(), null, clazz);
        String code = "{"
                + " if (!$1.startsWith(\"org.jboss.aop.\") &&"
                + " !$1.startsWith(\"javassist\") &&"
                + " !$1.startsWith(\"org.jboss.util.\") &&"
                + " !$1.startsWith(\"gnu.trove.\") &&"
                + " !$1.startsWith(\"EDU.oswego.cs.dl.util.concurrent.\") &&"
                // System classes
                + " !$1.startsWith(\"org.apache.\") &&"
                + " !$1.startsWith(\"org.gradle\") &&"
                + " !$1.startsWith(\"com.google\") &&"
                + " !$1.startsWith(\"ch.qos\") &&"
                + " !$1.startsWith(\"org.slf4j\") &&"
                + " !$1.startsWith(\"com.esotericsoftware\") &&"
//                + " !$1.startsWith(\"org.apache.xalan\") &&"
//                + " !$1.startsWith(\"org.apache.xml\") &&"
//                + " !$1.startsWith(\"org.apache.xpath\") &&"
//                + " !$1.startsWith(\"org.apache.tools\") &&"
                + " !$1.startsWith(\"org.ietf.\") &&"
                + " !$1.startsWith(\"org.omg.\") &&"
                + " !$1.startsWith(\"org.junit.\") &&"
                + " !$1.startsWith(\"org.w3c.\") &&"
                + " !$1.startsWith(\"org.xml.sax.\") &&"
                + " !$1.startsWith(\"sunw.\") &&"
                + " !$1.startsWith(\"sun.\") &&"
                + " !$1.startsWith(\"java.\") &&"
                + " !$1.startsWith(\"javax.\") &&"
                + " !$1.startsWith(\"com.sun.\") &&"
                + " !$1.startsWith(\"$Proxy\")) {"
                + " org.owasp.securt.AbstractTaintUtil.debug(\"Wrapping: \"+$1);"
                + "      byte[] newBytes = org.owasp.securt.InterfaceModifier.translate($1, $0, $2) ;"
                + "      if (newBytes != (byte[])null) {"
                + "         return wrappedDefineClass($1, newBytes, 0, newBytes.length, $5); "
                + "      }}"
                + "  return wrappedDefineClass($1, $2, $3, $4, $5); "
                + "  "
                + "}";
        wrapper.setBody(code);
        clazz.addMethod(wrapper);
    }
}
