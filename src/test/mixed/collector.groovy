class Collector {
    public String getInput() {
        String fileContents = new File('src/test/resources/file.txt').text
        return fileContents
    }
}