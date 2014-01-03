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
        // System.out.println("[*] options:"+java.util.Arrays.asList(args).toString());

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
            } else {
                g.createTaintUtil(destPath);
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

    private void createString(String destPath) throws NotFoundException, CannotCompileException, IOException {
        ClassPool cp = ClassPool.getDefault();
        CtClass cc = cp.get("java.lang.String");
        CtField f = new CtField(CtClass.booleanType, "tainted", cc);
        f.setModifiers(Modifier.PRIVATE);
        cc.addField(f);
        cc.addMethod(CtNewMethod.getter("isTainted", f));
        cc.addMethod(CtNewMethod.setter("setTaint", f));
        cc.writeFile(destPath);
        System.out.println("[*] Adapted: "+cc.getName());
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
        m.insertAfter("{$_.setTaint(tainted);}");
        cc.writeFile(destPath);
        System.out.println("[*] Adapted: "+cc.getName());
    }

    private static void createTaintUtil(String destPath) throws NotFoundException, CannotCompileException, IOException {

        ClassPool cp = ClassPool.getDefault();

        // Just a shortcut to copy the Superclass to the new destination
        CtClass atu = cp.get("org.owasp.securt.AbstractTaintUtil");
        atu.writeFile(destPath);

        CtClass cc = cp.makeClass("org.owasp.securt.TaintUtil", atu);

        cc.addMethod(CtNewMethod.make("public static void setTaint(String tainted, boolean taint) {if(tainted != null){tainted.setTaint(taint);}}", cc));
        cc.addMethod(CtNewMethod.make("public static void checkTaint(String tainted) {if(tainted.isTainted())markTaint();}", cc));

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
        System.out.println(String.format("[*] Processing %d elements of type %s", nList.getLength(), type));
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
        System.out.println(String.format("[*] Building sink for class: %s", clazz));
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
            System.out.println(String.format("[*]     modified method: %s", method.getName()));
            method.insertBefore("{org.owasp.securt.TaintUtil.checkTaint($" + vulnerable + ");}");
            result = true;
        } else {
            System.err.println(String.format("[E] %s does not take a String", method.getLongName()));
        }

        return result;
    }

    private void buildSource(String destPath, Element element, String clazz, String method, String arguments) throws NotFoundException, CannotCompileException, IOException {
        ClassPool cp = ClassPool.getDefault();
        CtClass cc = cp.get(clazz);
        boolean write = false;
        System.out.println(String.format("[*] Building source for class: %s", clazz));
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
            System.out.println(String.format("[*]     modified method: %s", method.getName()));
            method.insertAfter("{if($_ != null) $_.setTaint(true);}");
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

    protected void processInterfaces()  throws NotFoundException, CannotCompileException, IOException, SAXException, ParserConfigurationException {
        System.out.println("[*] Altering interface implementations");
        String fileName = Thread.currentThread().getContextClassLoader().getResource("securt.xml").getFile();
        System.out.println("[*] Using XML: "+fileName);

        File fXmlFile = new File(fileName);
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
        Document doc = dBuilder.parse(fXmlFile);
        String type = "interface";
        doc.getDocumentElement().normalize();
        NodeList nList = doc.getElementsByTagName(type);
        System.out.println(String.format("[*] Processing %d elements of type %s", nList.getLength(), type));
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
                buildInterface(eElement, clazz, method, arguments, vulnerable);
            }
        }     
    }

    private void buildInterface(Element element, String clazz, String method, String arguments, int vulnerable)  throws NotFoundException, CannotCompileException, IOException{
        buildSink(null, element, clazz, method, arguments, vulnerable);
    }
}
