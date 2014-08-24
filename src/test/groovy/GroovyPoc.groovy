import org.codehaus.groovy.runtime.typehandling.ShortTypeHandling

// Groovy PoC
String fileContents = new File('src/test/resources/file.txt').text
println "The contents of the file is: " +fileContents


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
println "The contents of the file is: " +getUserName()
