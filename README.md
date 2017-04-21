# MalCrawl

Crawler to identify malicious source code with the help of Machine Learning. This is a Cybersecurity and Machine Learning project. 
We are trying to use YARA rules. 

Requirements:
  tensorflow  
  sklearn

Create the directories ./Malware and ./Clean

Fill Malware with training malicious source code
Fill Clean with training clean source code

bagOfWordsClassifier.py:
  Uses a random forest with vectors based on number of occurrences of each word per file

yaraClassifier.py:
  Uses a support vector machine. Vectors contain results of scanning files with pre-defined YARA rules in YARA/rules.yar

sentimentClassifier.py:
  Uses a support vector machine. Performs topic modeling and sentiment analysis using term frequency-inverse document frequency vectorizer

wordEmbeddings.py:
  Creates word embeddings for malicious vocabulary