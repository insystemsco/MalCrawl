from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn import svm
from sklearn.metrics import classification_report
from sklearn.externals import joblib
from sklearn.cross_validation import cross_val_score

import os, mimetypes, string

# Reference: https://gist.github.com/bonzanini/c9248a239bbab0e0d42e#file-sentiment_classification-py-L41



# Global dict containing malicious and clean source code with labels
trainingData = {}
trainingData['files'] = []
trainingData['classification'] = []


# Traverses all files and directories starting from a root directory
# Adds normalized files to trainingData dict

def getCorpus(path, classification):
    
    print "Reading source code"
    
    for root, subFolders, fileNames in os.walk(path):
        for fileName in fileNames:

            # Learn type of file - only want text files
            fileType = mimetypes.guess_type(fileName)
            
            if (fileType[1] is None and fileType[0] is None) or (len(fileType[0]) >= 7 and (fileType[0][:7] == 'text/x-') or (len(fileType[0]) >= 10 and fileType[0][:10] == 'text/plain')):
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
                            tempString += character

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
2                        
            else:
                print "Skipping file: ", fileName, fileType

    return

def main(mPath, cPath):
    
    # Get input from files
    getCorpus(mPath, 'malware')
    print "Read malicious source code"

    getCorpus(cPath, 'clean')
    print "Read clean source code"

    print "Creating and fitting tfidf vectorizer"
    tfidfVectorizer = TfidfVectorizer(min_df=1, max_df=0.8, sublinear_tf=True, use_idf=True)
    trainingVectors = tfidfVectorizer.fit_transform(trainingData['files'])

    classifier = svm.LinearSVC()

    print "Training classifier"
    classifier.fit(trainingVectors, trainingData['classification'])

    print "Saving classifier"
    joblib.dump(classifier, "sentimentClassifier.pkl")
    print "Saved to classifier.pkl"

    print "Performing cross validation tests"
    numValidations = 10
    scores = cross_val_score(classifier, trainingVectors, trainingData['classification'], cv=numValidations)

    print "\nResults of cross validation tests:"
    for i in range(numValidations):
        print "\t",scores[i]

main("Malware", "Clean")    
