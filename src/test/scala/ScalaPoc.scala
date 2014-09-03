val source = scala.io.Source.fromFile("src/test/resources/file.txt")
val lines = source.mkString
source.close()
println ("The contents of the file is: " + lines)

val bs = BufferedSource
