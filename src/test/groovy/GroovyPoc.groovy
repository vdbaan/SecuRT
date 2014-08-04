
// Groovy PoC
String fileContents = new File('src/test/resources/file.txt').text

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