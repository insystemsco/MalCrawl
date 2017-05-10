from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn import svm
from sklearn.metrics import classification_report
from sklearn.externals import joblib
from sklearn.cross_validation import cross_val_score
from bs4 import BeautifulSoup

import urllib, urlparse, re, os, string, requests, mimetypes, json, random

token = { "access_token":"4d3c1f468ef34ed72cd70b09762e49c372c4d928" }

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

def getCorpus(url):

    req  = requests.get(url)
    text = req.text
    
    tempString = ""
    tempFile = []
                    
    # Read in and normalize strings. 
    for character in text:
                    
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
        return " ".join(tempFile)
                        
    return ""


def addOAuthToken(url):

    urlList = list(urlparse.urlparse(url))
    params = dict(urlparse.parse_qsl(urlList[4]))

    params.update(token)

    urlList[4] = urllib.urlencode(params)
    url = urlparse.urlunparse(urlList)
    
    return url                                                                                                                        


def crawl(vectorizer, classifier):

    cutoff = 80
    responseJson = {}
    
    links = []
    sourceCodeUrls = []
    sourceCode = []

    """
    
    # Keep trying to find an available repository
    while not responseJson.get("url"):

        # 57 million repositories as of april 2017, get a random one
        randRepositoryId = random.randint(0, 57000000)
        url = "https://api.github.com/repositories/{}".format(randRepositoryId)
        url = addOAuthToken(url)       
        response  = requests.get(url)
        responseJson = json.loads(response.text)

    apiUrl = responseJson["url"] + "/contents/"

    #githubUrl = "https://github.com/joyce8/MalCrawl/"
    githubUrl = "https://github.com/tim-lau/merging-data/tree/master/css"
    ownerRepo = re.search("https:\/\/github\.com\/(.+)", githubUrl).groups()[0]
    apiUrl = "https://api.github.com/repos/{}/contents".format(ownerRepo)
    print "Crawling " + apiUrl

    """
    apiUrl = "https://api.github.com/repos/fdiskyou/malware/contents/TinyNuke"
    #apiUrl = "https://api.github.com/repos/fdiskyou/malware/contents/ZeroAccess"
    #apiUrl = "https://api.github.com/repos/fdiskyou/malware/contents/Trochilus"
    #apiUrl = "https://api.github.com/repos/fdiskyou/malware/contents/Pony"
    #apiUrl = "https://api.github.com/repos/fdiskyou/malware/contents/Hidden-tear"
    #apiUrl = "https://api.github.com/repos/fdiskyou/malware/contents/Eda2"
    #apiUrl = "https://api.github.com/repos/fdiskyou/malware/contents/Crimepack3.1.3"
    #apiUrl = "https://api.github.com/repos/gbrindisi/malware/contents/android/gmbot"
    
    
    #ownerRepo = re.search("https:\/\/api.github\.com\/repos\/(.+)/contents/", apiUrl).groups()[0]
    #githubUrl = "https://github.com/{}".format(ownerRepo)
    #print "Crawling " + str(githubUrl)    
    
    apiUrl = addOAuthToken(apiUrl)
    print "apiUrl: ", apiUrl
    response = requests.get(apiUrl)
    contents = json.loads(response.text)

    for link in contents:
        #print link
        if link.get("type"):
            links.append([link["download_url"], link["type"], link["url"]])
                    
    # Breadth-first search through all github directories
    while len(links) > 0:

        # Process a file
        if links[0][1] == "file":
            
            fileType = mimetypes.guess_type(links[0][0])

            if (fileType[1] is None and fileType[0] is None) or re.match(combinedMimeRegex, fileType[0]):
                tempApiUrl = addOAuthToken(links[0][0])
                #print "tempApiUrlFile", tempApiUrl
                sourceCodeUrls.append(tempApiUrl)

        # Process adirectory, adding all of its files and subdirectories
        elif links[0][1] == "dir":

            tempApiUrl = addOAuthToken(links[0][2])
            urlList = list(urlparse.urlparse(tempApiUrl))
            #print "tempApiUrlDir: ", tempApiUrl
            response = requests.get(tempApiUrl)
            contents = json.loads(response.text)

            for link in contents:
                if link.get("type"):
                    links.append([link["download_url"], link["type"], link["url"]])

        else:
            print "Failed to process link: ", links[0]
            
        # Done with current file/directory
        links.pop(0)
        
    for url in sourceCodeUrls:
        sourceCode.append(getCorpus(url))

    
    if len(sourceCode) > 0:

        malCount = 0.0
        cleanCount = 0.0

        print "Predicting..."
        vector = vectorizer.transform(sourceCode)    
        results = classifier.predict(vector)
        
        for i in range(len(results)):
            if results[i] == "malware":
                malCount += 1
            else:
                cleanCount -= 1

        malScore = (malCount + cleanCount) / len(results) * 100.0

        if malScore > cutoff:
            print "MALICIOUS | score: " + str(malScore) + " | malicious: " + str(malCount) + " | clean: " + str(cleanCount * -1)
            
        else:
            print "CLEAN | score: " + str(malScore) + " | malicious: " + str(malCount) + " | clean: " + str(cleanCount * -1)

        print
            
    else:
        print "No readable source code"   


def main(vectorizerPath, classifierPath):
        
    print "Loading pkl files"
    vectorizer = joblib.load(vectorizerPath)
    classifier = joblib.load(classifierPath)

    while True:
        crawl(vectorizer, classifier)

        
main("PKL/tfidfVectorizer.pkl", "PKL/topicModelingClassifier.pkl")    
#main("PKL/countVectorizer.pkl", "PKL/bagOfWordsClassifier.pkl")