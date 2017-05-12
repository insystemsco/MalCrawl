from sklearn.feature_extraction import DictVectorizer
from sklearn import svm
from sklearn.metrics import classification_report
from sklearn.externals import joblib
from sklearn.cross_validation import cross_val_score

import os, subprocess, copy

# Each value in the vector corresponds to the number of times each yara rule hits, normalized by # of files scanned

yaraDict = {}

# Parse YARA file and use it to initialize yaraDict
# Key: Yara rule name, Value: 0
def yaraDictInit():

    with open("./YARA/heuristics.yar") as f:

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
                
            # Scan repository with 3 sets of YARA rules
            subproc = subprocess.Popen(["yara", "./YARA/heuristics.yar", os.path.join(root, fileName)], stdout=subprocess.PIPE)
            
            # Record number of hits into dictionary
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
        print "Scanning malware repository", repository, "...",
        trainingData['files'].append(yaraScanDir(repository))
        trainingData['classification'].append("malware")
        print "Done."
        
    for repository in cRepositories:
        print "Scanning clean repository", repository, "...",
        trainingData['files'].append(yaraScanDir(repository))
        trainingData['classification'].append("clean")
        print "Done."
                
    # DictVectorizer
    print "Creating and fitting dict vectorizer"
    dictVectorizer = DictVectorizer(sparse=False)
    trainingVectors = dictVectorizer.fit_transform(trainingData['files'])

    classifier = svm.LinearSVC()

    print "Training YARA classifier"
    classifier.fit(trainingVectors, trainingData['classification'])

    print "Saving YARA classifier"
    joblib.dump(classifier, "yaraClassifier.pkl")
    print "Saved to yaraClassifier.pkl"

    print "Performing cross validation tests"
    numValidations = 10
    scores = cross_val_score(classifier, trainingVectors, trainingData['classification'], cv=numValidations)

    print "\nResults of cross validation tests:"
    for i in range(numValidations):
        print "\tTest " + str(i) + ": " + str(scores[i] * 100) + "%"
        
    print
        
main("Malware", "Clean")
