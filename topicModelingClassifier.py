from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn import svm
from sklearn.metrics import classification_report
from sklearn.externals import joblib
from sklearn.cross_validation import cross_val_score

import os, mimetypes, string, re

# Global dict containing malicious and clean source code with labels
trainingData = {}
trainingData['files'] = []
trainingData['classification'] = []

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
                        trainingData['files'].append(" ".join(tempFile))
                        trainingData['classification'].append(classification)
                        
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
    
    print "Creating and fitting tfidf vectorizer"
    tfidfVectorizer = TfidfVectorizer()
    trainingVectors = tfidfVectorizer.fit_transform(trainingData['files'])
                                                                 
    # Create support vector machine
    classifier = svm.LinearSVC()

    # Train support vector machine
    print("Training linear support vector machine")
    classifier.fit(trainingVectors, trainingData['classification'])
    print("Support vector machine trained!")

    # Save support vector machine to disk
    print("Saving support vector machine to disk")
    joblib.dump(classifier, "topicModelingClassifier.pkl")

    # Measure accuracy of support vector machine    
    print("Performing cross validation tests")
    scores = cross_val_score(classifier, trainingVectors, trainingData['classification'], cv=numValidations)
    print "\nAccuracy of each cross-validation test:"
    for i in range(numValidations):
        print "\tTest " + str(i) + ": " + str(scores[i] * 100) + "%"

    print
        
main("Malware", "Clean")    
