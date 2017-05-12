# MalCrawl

Crawler to identify malicious source code on GitHub with the help of Machine Learning. This is a Cybersecurity and Machine Learning project. 

Requirements:
* sklearn
* reverend

YARA directory contains all rules used by yaraClassifier


Machine Learning Classifiers:

    yaraClassifier.py:
        * Run to train a support vector machine. Vectors contain results of scanning files with pre-defined YARA rules in YARA/rules.yar

    bagOfWordsClassifier.py:
        * Run to train a support vector machine. Vectors contain number of occurrences of each word per file

    topicModelingClassifier.py:
        * Run to train a support vector machine. Performs topic modeling and sentiment analysis using term frequency-inverse document frequency vectorizer

    bayesianClassifier.py
        * Run to train a bayesian network classifier.

Directories

    Malware:
        * Fill with malicious source code training set

    Clean:
        * Fill with clean source code training set

    YARA:
        * Fill with any rules used by the YARA classifier. Contains heuristics.yar by default

    PKL:
        * Fill with any .pkl files generated by the classifiers

Crawlers

    malcrawlText.py
        * Crawler for the bag-of-words and topic modeling classifiers

    malcrawlBayes.py
        * Crawler for the bayesian classifier