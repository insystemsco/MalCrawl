from gensim.models import word2vec
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.externals import joblib
from sklearn.cross_validation import cross_val_score

import os, numpy, copy, math, string, mimetypes

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
                        
            else:
                print "Skipping file: ", fileName, fileType

    return

def main(mPath, cPath):

    # Get input from files
    getCorpus(mPath, 'malware')
    print "Read malicious source code"

    getCorpus(cPath, 'clean')
    print "Read clean source code"

    # CountVectorizer uses # of words - will want to improve to TF/IDF later
    print "Setting up CountVectorizer"
    trainingVectorizer = CountVectorizer(stop_words='english')
    trainingFitTransform = trainingVectorizer.fit_transform(trainingData['files'])
    trainingFitTransform = trainingFitTransform.toarray()

    # Create random forest
    randomForest = RandomForestClassifier(n_estimators=100)
    randomForest.classes_ = trainingData['classification']

    # Train random forest
    print("Training random forest")
    randomForest = randomForest.fit(trainingFitTransform, trainingData['classification'])
    print("Random forest trained!")

    # Save random forest to disk
    print("Saving random forest to disk")
    joblib.dump(randomForest, "bagOfWordsClassifier.pkl")

    # Apply tests to random forest
    print("Performing cross validation tests")
    scores = cross_val_score(randomForest, trainingFitTransform, trainingData['classification'], cv=5)
    print "\nAccuracy of each cross-validation test:"
    for score in scores:
        print score
        

main("Malware", "Clean")    
