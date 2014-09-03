__author__ = 'steven'
import sys

my_file = open('src/test/resources/file.txt','w')
lines = my_file.readlines()
sys.stdout.println("The contents of the file is: %s" %lines)