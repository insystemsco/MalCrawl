from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn import svm
from sklearn.metrics import classification_report
from sklearn.externals import joblib
from sklearn.cross_validation import cross_val_score

import os, mimetypes, string, re

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

# Join all mimeRegexes as ( )|( )|( )
combinedMimeRegex = "(" + ")|(".join(mimeRegexes) + ")"

# Traverses all files and directories starting from a root directory
# Adds normalized files to trainingData dict

def getCorpus(path):

    sourceCode = []
    
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
                        sourceCode.append(" ".join(tempFile))
                        
    return sourceCode

# scPath - Path to source code
# pklPath - Path to .pkl file

def main(mPath, cPath, vectorizerPath, classifierPath):

    print "Loading pkl files"
    vectorizer = joblib.load(vectorizerPath)
    classifier = joblib.load(classifierPath)

    # Get a list of all malware and clean github repositories
    mRepositories = []
    for repository in os.listdir(os.path.join('.', mPath)):
        if os.path.isdir(os.path.join('.', mPath, repository)):
            mRepositories.append(os.path.join('.', mPath, repository))

    cRepositories = []
    for repository in os.listdir(os.path.join('.', cPath)):
        if os.path.isdir(os.path.join('.', cPath, repository)):
            cRepositories.append(os.path.join('.', cPath, repository))

    cutoff = 80
            
    malwareRepositories = 0
    cleanRepositories = 0

    correctMalwareRepositories = 0
    correctCleanRepositories = 0
            
    # Score all malware repositories
    for repository in mRepositories:
        
        sourceCode = getCorpus(repository)

        if len(sourceCode) > 0:

            malwareRepositories += 1
            malCount = 0.0

            vector = vectorizer.transform(sourceCode)    
            results = classifier.predict(vector)
        
            for i in range(len(results)):
                if results[i] == "malware":
                    malCount += 1
                else:
                    malCount -= 1

            malScore = malCount / len(results) * 100.0

            if malScore > cutoff:
                print str(repository) + " is MALICIOUS | score: " + str(malScore)
                correctMalwareRepositories += 1

            else:
                print str(repository) + "is CLEAN | score: " + str(malScore)

        else:
            print str(repository) + " has no readable source code"
                
    # Score all clean repositories
    for repository in cRepositories:

        sourceCode = getCorpus(repository)

        if len(sourceCode) > 0:
            
            cleanRepositories += 1
            malCount = 0.0

            vector = vectorizer.transform(sourceCode)
            results = classifier.predict(vector)
        
            for i in range(len(results)):
                if results[i] == "malware":
                    malCount += 1
                else:
                    malCount -= 1

            malScore = malCount / len(results) * 100.0

            if malScore > cutoff:
                print str(repository) + " is MALICIOUS | score: " + str(malScore)

            else:
                print str(repository) + " is CLEAN | score: " + str(malScore)
                correctCleanRepositories += 1                

        else:
            print str(repository) + " has no readable source code"

    print "Malicious cutoff score: " + str(cutoff) + "%"
    print "Number of malware repositories: " + str(malwareRepositories)
    print "Number of malware repositories correctly classified: " + str(correctMalwareRepositories)
    print "Number of clean repositories: " + str(cleanRepositories)
    print "Number of clean repositories correctly classified: " + str(correctCleanRepositories)
            
#main("Malware", "Clean", "PKL/tfidfVectorizer.pkl", "PKL/topicModelingClassifier.pkl")    
main("Malware", "Clean", "PKL/countVectorizer.pkl", "PKL/bagOfWordsClassifier.pkl")
