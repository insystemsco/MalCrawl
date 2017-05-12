from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn import svm
from sklearn.metrics import classification_report
from sklearn.externals import joblib
from sklearn.cross_validation import cross_val_score
from bs4 import BeautifulSoup

import urllib, urlparse, re, os, string, requests, mimetypes, json, random

# Replace "INSERT_OAUTH_TOKEN_HERE" with your GitHub OAuth token
token = { "access_token":"INSERT_OAUTH_TOKEN_HERE" }

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
        
    # Keep trying to find an available repository
    while not responseJson.get("url"):

        # 57 million repositories as of april 2017, get a random one
        randRepositoryId = random.randint(0, 57000000)
        url = "https://api.github.com/repositories/{}".format(randRepositoryId)
        url = addOAuthToken(url)       
        response  = requests.get(url)
        responseJson = json.loads(response.text)

    apiUrl = responseJson["url"] + "/contents/"    
    
    ownerRepo = re.search("https:\/\/api.github\.com\/repos\/(.+)/contents/", apiUrl).groups()[0]
    githubUrl = "https://github.com/{}".format(ownerRepo)
    print "Crawling " + str(githubUrl)    
    
    apiUrl = addOAuthToken(apiUrl)
    response = requests.get(apiUrl)
    contents = json.loads(response.text)

    for link in contents:
        if not isinstance(link, unicode) and link.get("type"):
            links.append([link["download_url"], link["type"], link["url"]])
                    
    # Breadth-first search through all github directories
    while len(links) > 0:

        # Process a file
        if links[0][1] == "file":

            fileType = None
            if isinstance(links[0][0], unicode):
                fileType = mimetypes.guess_type(links[0][0])
            
            if fileType is not None:
                if (fileType[1] is None and fileType[0] is None) or re.match(combinedMimeRegex, fileType[0]):
                    tempApiUrl = addOAuthToken(links[0][0])
                    sourceCodeUrls.append(tempApiUrl)

        # Process adirectory, adding all of its files and subdirectories
        elif links[0][1] == "dir":

            tempApiUrl = addOAuthToken(links[0][2])
            urlList = list(urlparse.urlparse(tempApiUrl))
            response = requests.get(tempApiUrl)
            contents = json.loads(response.text)

            for link in contents:
                if not isinstance(link, unicode) and link.get("type"):
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

            
    else:
        print "No readable source code"   

    print

def main(vectorizerPath, classifierPath):
        
    print "Loading pkl files"
    vectorizer = joblib.load(vectorizerPath)
    classifier = joblib.load(classifierPath)
    
    while True:
        crawl(vectorizer, classifier)

        
main("PKL/tfidfVectorizer.pkl", "PKL/topicModelingClassifier.pkl")    
#main("PKL/countVectorizer.pkl", "PKL/bagOfWordsClassifier.pkl")
