#My list of "Sources", "Sinks" and "Sanitization" methods
#Sources:
###javax.servlet.ServletRequest (I)
- getAttribute
- getAttributeNames
- getCharacterEncoding
- getContentType
- getParameter
- getParameterNames
- getParameterValues
- getParameterMap
- getProtocol
- getScheme
- getServerName
- getRemoteAddr
- getRemoteHost
- getLocalName
- getLocalAddr
- getReader

###javax.servlet.http.HttpServletRequest (I)
- getAuthType
- getHeader
- getHeaders
- getMethod
- getPathInfo
- getPathTranslated
- getContextPath
- getQueryString
- getRemoteUser
- getRequestedSessionId
- getRequestURI
- getRequestURL
- getServletPath

###javax.servlet.http.Cookie
- getComment
- getDomain
- getPath
- getName
- getValue

###javax.servlet.ServletConfig (I)
- getInitParameter
- getInitParameterNames

###javax.servlet.GenericServlet (A)
- getInitParameter
- getInitParameterNames

###java.sql.ResultSet (I)
- getString
- getString

###java.awt.TextComponent
- getSelectedText
- getText

###java.io.Console
- readLine
- readPassword

###java.io.DataInputStream
- readLine
- readUTF

###java.io.LineNumberReader (extends BufferedReader)
- readLine

###javax.servlet.http.HttpSession (I)
- getAttribute
- getAttributeNames
- getValue
- getValueNames

###java.lang.System
- getProperty -> uses java.util.Properties.getProperty
- getProperties
- getenv

###javax.servlet.ServletContext (I)
- getResourceAsStream
- getRealPath
- getHeaderNames

###java.util.Properties
- getProperty

###java.lang.Class
- getResource
- getResourceAsStream

###org.apache.xmlrpc.XmlRpcClient (?)
- execute
- search

###javax.xml.xpath.XPath (I)
- evaluate

###javax.xml.xpath.XPathExpression (I)
- evaluate

#Sanitization:
###org.owasp.encoder.Encode (?)
- forHtml
- forHtmlContent
- forHtmlAttribute
- forHtmlUnquotedAttribute
- forCssString
- forCssUrl
- forUri
- forUriComponent
- forXml
- forXmlContent
- forXmlAttribute
- forXmlComment
- forCDATA
- forJava
- forJavaScript
- forJavaScriptAttribute
- forJavaScriptBlock
- forJavaScriptSource

###java.net.URLEncoder
- encode

###java.net.URLDecoder
- decode

###org.apache.commons.lang.StringEscapeUtils (?)
- escapeJava
- escapeJavaScript
- unescapeJava
- unescapeJavaScript
- escapeHtml
- unescapeHtml
- escapeXml
- unescapeXml
- escapeSql
- escapeCsv
- unescapeCsv

#Sinks:

##Command Injection
###java.lang.Runtime
- exec

###javax.xml.xpath.XPath (I)
- compile

###java.lang.Thread
- sleep(i)

###java.lang.System
- load
- loadLibrary

###org.apache.xmlrpc.XmlRpcClient (?)
- XmlRpcClient
- execute
- executeAsync

##Cookie Poisoning
###javax.servlet.http.Cookie
- Cookie
- setComment
- setDomain
- setPath
- setValue

##Cross Site Scripting
###java.io.PrintWriter
- print
- println
- write

###javax.servlet.ServletOutputStream (A)
- print
- println

###javax.servlet.jsp.JspWriter (A)
- print
- println

###javax.servlet.ServletRequest (I)
- setAttribute
- setCharacterEncoding

###javax.servlet.http.HttpServletResponse (I)
- sendError
- setDateHeader
- addDateHeader
- setHeader
- addHeader
- setIntHeader
- addIntHeader

###javax.servlet.ServletResponse (I)
- setCharacterEncoding
- setContentType

###javax.servlet.http.HttpSession (I)
- setAttribute
- putValue

##HTTP Response Splitting
###javax.servlet.http.HttpServletResponse (I)
- sendRedirect
- getRequestDispatcher

##LDAP Injection
###javax.naming.directory.InitialDirContext
- InitialDirContext
- search

###javax.naming.directory.SearchControls
- setReturningAttributes
- connect
- search

##Log Forging
###java.io.PrintStream
- print
- println

###java.util.logging.Logger
- config
- fine
- finer
- finest
- info
- warning
- severe
- entering
- log

###org.apache.commons.logging.Log (?)
- debug
- error
- fatal
- info
- trace
- warn

###java.io.BufferedWriter
- write

###javax.servlet.ServletContext (I)
- log

###javax.servlet.GenericServlet (A)
- log

##Path Traversal
###java.io
- File
- RandomAccessFile
- FileReader
- FileInputStream
- FileWriter
- FileOutputStream

###java.lang.Class
- getResource
- getResourceAsStream

###javax.mail.internet.InternetAddress
- InternetAddress
- parse

##Reflection Injection
###java.lang.Class
- forName
- getField
- getMethod
- getDeclaredField
- getDeclaredMethod

##Security Misconfiguration
###java.sql.DriverManager
- getConnection

##SQL Injection
###java.sql.(Prepared)?Statement (I)
- addBatch
- execute
- executeQuery
- executeUpdate

###java.sql.Connection (I)
- prepareStatement
- prepareCall

###javax.persistence.EntityManager (?)
- createNativeQuery
- createQuery

###(org|net.sf).hibernate.Session (?)
- createSQLQuery
- createQuery
- find
- delete
- save
- saveOrUpdate
- update
- load

##XPath Injection
###javax.xml.xpath.XPath (I)
- compile
- evaluate

###javax.xml.xpath.XPathExpression (I)
- evaluate

###org.apache.xpath.XPath (?)
- XPath

###org.apache.commons.jxpath.JXPath (?)
- getValue

###org.xmldb.api.modules.XPathQueryService (?)
- query

###org.xmldb.api.modules.XMLResource (?)
- setContent
