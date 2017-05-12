import os, mimetypes, string, re
from reverend.thomas import Bayes
import reverend
import pickle
import types

mimeRegexes = [
    "text",
    "application\/javascript",
    "application\/xml",
    "application\/svg\+xml",
    "application\/postcript",
    "application\/x-sql",
    "application\/json",
    "application\/x-msdos-program",
    "application\/x-ruby",
    "application\/rtf"
]

numValidations = 10

# Join all mimeRegexes as ( )|( )|( )
combinedMimeRegex = "(" + ")|(".join(mimeRegexes) + ")"

#http://stackoverflow.com/questions/15499170/how-to-remove-instancemethod-objects-for-the-sake-of-pickle-without-modifying
#For saving the pickle file.

def Bayes__getstate__(self):
    state = {}
    for attr, value in self.__dict__.iteritems():
        if not isinstance(value, types.MethodType):
            state[attr] = value
        elif attr == 'combiner' and value.__name__ == 'robinson':
            # by default, self.combiner is set to self.robinson
            state['combiner'] = None
    return state

def Bayes__setstate__(self, state):
    self.__dict__.update(state)
    # support the default combiner (an instance method):
    if 'combiner' in state and state['combiner'] is None:
        self.combiner = self.robinson

Bayes.__getstate__ = Bayes__getstate__
Bayes.__setstate__ = Bayes__setstate__

bayes = Bayes()


# Traverses all files and directories starting from a root directory
# Adds normalized files to trainingData dict

def getCorpus(path, classification):
    
    for root, subFolders, fileNames in os.walk(path):
        for fileName in fileNames:

            # Learn type of file - only want text files
            fileType = mimetypes.guess_type(fileName)
            
            if (fileType[1] is None and fileType[0] is None) or re.match(combinedMimeRegex, fileType[0]):
                with open(os.path.join(root, fileName), 'rb') as f:

                    tempString = ""
                    tempFile = []
                    
                    # Read in and normalize strings. 
                    for character in f.read():
                    
                        if character in string.letters:
                            tempString += character.lower()
                            
                        elif character in string.digits:
                            tempString += character
                        
                        elif character in ['-', '_']:
                            pass
                            
                        elif len(tempString) >= 4 and len(tempString) <= 25:
                            tempFile.append(tempString)
                            tempString = ""

                        else:
                            tempString = ""

                    # If the end of the file is reached, check if fString is a valid word
                    if len(tempString) >= 4 and len(tempString) <= 25:
                        tempFile.append(tempString)

                    # Add file to trainingData
                    if len(tempFile) > 0:
                        tempFile = str(tempFile)
                        bayes.train(classification,tempFile)
                        
            else:
                print "Skipping file: ", fileName, fileType

    return

def testCorpus(path):
    
    for root, subFolders, fileNames in os.walk(path):
        for fileName in fileNames:

            # Learn type of file - only want text files
            fileType = mimetypes.guess_type(fileName)
            
            if (fileType[1] is None and fileType[0] is None) or re.match(combinedMimeRegex, fileType[0]):
                with open(os.path.join(root, fileName), 'rb') as f:

                    tempString = ""
                    tempFile = []
                    
                    # Read in and normalize strings. 
                    for character in f.read():
                    
                        if character in string.letters:
                            tempString += character.lower()
                            
                        elif character in string.digits:
                            tempString += character
                        
                        elif character in ['-', '_']:
                            pass
                            
                        elif len(tempString) >= 4 and len(tempString) <= 25:
                            tempFile.append(tempString)
                            tempString = ""

                        else:
                            tempString = ""

                    # If the end of the file is reached, check if fString is a valid word
                    if len(tempString) >= 4 and len(tempString) <= 25:
                        tempFile.append(tempString)

                    # Add file to trainingData
                    if len(tempFile) > 0:
                        guess = bayes.guess(str(tempFile))
                        print guess

                        
            else:
                print "Skipping file: ", fileName, fileType

    return

def main(mPath, cPath):

    # Get input from files
    print "Reading malicious source code"
    getCorpus(mPath, 'malware')
    print "Finished reading malicious source code"

    print "Reading clean source code"
    getCorpus(cPath, 'clean')
    print "Finished reading clean source code"

    print "Lets guess"
    testCorpus("TestData")

    bayes.save('Bayes.pkl')
    
main("Malware", "Clean")    