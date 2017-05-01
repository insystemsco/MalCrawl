# MalCrawl

Crawler to identify malicious source code on GitHub with the help of Machine Learning. This is a Cybersecurity and Machine Learning project. 

Requirements:
  sklearn

Fill Malware with training malicious source code
Fill Clean with training clean source code

YARA directory contains all rules used by yaraClassifier

PKL contains classifiers saved in .pkl format

yaraClassifier.py:
  Run to train a support vector machine. Vectors contain results of scanning files with pre-defined YARA rules in YARA/rules.yar

bagOfWordsClassifier.py:
  Run to train a support vector machine. Vectors contain number of occurrences of each word per file

topicModelingClassifier.py:
  Run to train a support vector machine. Performs topic modeling and sentiment analysis using term frequency-inverse document frequency vectorizer