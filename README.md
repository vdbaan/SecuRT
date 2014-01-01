SecuRT
======

SecuRT is trying to be a classpath addition for security **testing** 
purposes. It provides *Taint* tracing functionality to identify potential 
source-sink problems on a basic level; through the String class.

**Note: It is not designed to be used in production environments.**

SecuRT adapts the **java.lang.String class** and adds a taint property. 
This property identifies if a String was created from a *dirty source*. 
When a tainted String reaches a method that has been identified as a sink, 
the String will be checked and, if the taint == true, either a exception 
will be thrown or a message will be written to the System.error.

###Usage###
When a good jar is created, a defined usage will be written down. For now
*read the code*.

####Future Features####
+ Use an XML document for identifying sources and sinks
+ Anotate source/sink interface methods on the fly
+ Make a J2EE PoC
