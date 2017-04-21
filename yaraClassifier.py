from sklearn.feature_extraction import DictVectorizer
from sklearn import svm
from sklearn.metrics import classification_report
from sklearn.externals import joblib
from sklearn.cross_validation import cross_val_score

import os, mimetypes, subprocess, copy

# Each value in the vector corresponds to the number of times each yara rule hits, normalized by # of files scanned

yaraDict = {}

# Parse YARA file and use it to initialize yaraDict
# Key: Yara rule name, Value: 0
def yaraDictInit():

    with open("./YARA/rules.yar") as f:

        for line in f.readlines():
            
            line = line.split()
            if len(line) > 1  and line[0] == "rule":
                yaraDict[line[1]] = 0

    return

# Opens one github repository and scans it with YARA. Returns results in a dict
def yaraScanDir(path):

    numScanned = 0
    
    # Copy initialized yaraDict for local use
    yaraResults = copy.deepcopy(yaraDict)
    
    for root, subFolders, fileNames in os.walk(path):
        for fileName in fileNames:

            # Learn type of file - only want text files
            fileType = mimetypes.guess_type(fileName)
            
            if (fileType[1] is None and fileType[0] is None) or (len(fileType[0]) >= 7 and (fileType[0][:7] == 'text/x-') or (len(fileType[0]) >= 10 and fileType[0][:10] == 'text/plain')):

                #print fileName
                
                # Scan repository with YARA
                subproc = subprocess.Popen(["yara", "./YARA/rules.yar", os.path.join(root, fileName)], stdout=subprocess.PIPE)

                # Record number of hits into a dictionary
                for line in iter(subproc.stdout.readline, ''):
                    line = line.split()
                    yaraResults[line[0]] += 1                    

                numScanned += 1

    # Normalize by number of files in repository
    for key in yaraResults.keys():
        if numScanned > 0:
            yaraResults[key] /= float(numScanned)


    #print "numScanned: ", numScanned
    return yaraResults


def main(mPath, cPath):

    yaraDictInit()

    trainingData = {}
    trainingData['files'] = []
    trainingData['classification'] = []
    
    # get a list of all malware and clean github repositories
    mRepositories = []
    for repository in os.listdir(os.path.join('.', mPath)):
        if os.path.isdir(os.path.join('.', mPath, repository)):
            mRepositories.append(os.path.join('.', mPath, repository))
                                
    cRepositories = []
    for repository in os.listdir(os.path.join('.', cPath)):
        if os.path.isdir(os.path.join('.', cPath, repository)):
            cRepositories.append(os.path.join('.', cPath, repository))                    

    # Call yaraScanDir on all malicious and clean repositories
    for repository in mRepositories:
        trainingData['files'].append(yaraScanDir(repository))
        trainingData['classification'].append("malware")
        print "Scanned malware repository", repository
        
    for repository in cRepositories:
        trainingData['files'].append(yaraScanDir(repository))
        trainingData['classification'].append("clean")
        print "Scanned clean repository", repository
                
    # DictVectorizer
    dictVectorizer = DictVectorizer(sparse=False)
    trainingVectors = dictVectorizer.fit_transform(trainingData['files'])

    classifier = svm.LinearSVC()

    print "Training classifier"
    classifier.fit(trainingVectors, trainingData['classification'])

    print "Saving classifier"
    joblib.dump(classifier, "yaraClassifier.pkl")
    print "Saved to yaraClassifier.pkl"

    print "Performing cross validation tests"
    numValidations = 10
    scores = cross_val_score(classifier, trainingVectors, trainingData['classification'], cv=numValidations)

    print "\nResults of cross validation tests:"
    for i in range(numValidations):
        print "\t",scores[i]
    
main("Malware", "Clean")
