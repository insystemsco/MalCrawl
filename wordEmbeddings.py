import tensorflow
import collections
import mimetypes
import fnmatch
import random
import numpy
import string
import math
import os
import re

from sklearn.manifold import TSNE
import matplotlib.pyplot as plt

VOCABULARY_SIZE = 50000
NUM_TRAINING_STEPS = 100001


# Traverses all files and directories starting from a root directory
# Generator that yields all strings of length >= 4

def generateWordList():

    print "Reading source code"
    for root, subFolders, fileNames in os.walk('Malware'):
        for fileName in fileNames:

            # Learn type of file - only want text files
            typeGuess = mimetypes.guess_type(fileName)
            #print "typeGuess:", typeGuess, fileName, typeGuess[0], typeGuess[1]

            # add: text/x-sh
            
            if (typeGuess[1] is None and typeGuess[0] is None) or (len(typeGuess[0]) >= 7 and (typeGuess[0][:7] == 'text/x-') or (len(typeGuess[0]) >= 10 and typeGuess[0][:10] == 'text/plain')):
                with open(os.path.join(root, fileName), 'rb') as f:
                    fString = ""

                    # Read in and normalize strings
                    for character in f.read():
                    
                        if character in string.letters:
                            #fString += character.lower()
                            fString += character
                            continue

                        elif character in string.digits:
                            fString += character
                            continue

                        # Base64 characters
                        #elif character in ['+', '/', '=']:
                        #    fString += character
                        #    continue
                        
                        elif character in ['-', '_']:
                            #fString += character
                            continue

                        elif len(fString) >= 4 and len(fString) <= 25:
                            yield fString

                        fString = ""

                    # If the end of the file is reached, yield current value of fString if it has length >= 4
                    if len(fString) >= 4 and len(fString) <= 25:
                        yield fString


            else:
                print "Skipping file: ", fileName, typeGuess
                
    print "... done"

    
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# The following functions are heavily based on https://github.com/tensorflow/tensorflow/blob/master/tensorflow/examples/tutorials/word2vec/word2vec_basic.py  #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    
# Takes in the word list and returns:
# A list of tuples containing each word and the number of times it appears in the corpus
# A dictionary mapping each word to its index in the word count list
# A dictionary that is a reverse of the previous dictionary, mapping the index to the word
# A list that holds the dictionary index of each word for each word in the corpus

def createDictionary():

    # Use collections library to identify + count 50,000 most common words in wordlist.
    # Words not in the 50,000 most common are replaced with 'unknown_word'
    unknownCount = 0
    wordCount = [['unknown_word', unknownCount]]

    # word list generator
    print "Creating generator"
    wordListGenerator = generateWordList()
    print "Created generator", wordListGenerator  

    # Generate words
    words = list(wordListGenerator)
    
    wordCount.extend(collections.Counter(words).most_common(VOCABULARY_SIZE - 1))
    print "mostCommon:", wordCount[:10]
    print "done printing most common"
    
    # Create word dictionary. The key is the word and the value is its index in wordCount
    wordDict = {}
    for wordTuple in wordCount:
        wordDict[wordTuple[0]] = len(wordDict)
        
    # Create a reverse word dictionary with the wordCount index as the value and the word as the value
    reverseWordDict = dict(zip(wordDict.values(), wordDict.keys()))
        
    # Create a list of word indices to map each word in the corpus to its index in reverseWordDict and wordCount
    wordIndices = []
    for word in words:

        if word in wordDict:
            wordIndex = wordDict[word]
        else:
            wordIndex = wordDict['unknown_word']
            unknownCount += 1
        
        wordIndices.append(wordIndex)

    # Free up memory
    del words
        
    # Note that wordCount[0][0] = 'unknown_word'
    wordCount[0][1] = unknownCount
    
    return wordCount, wordDict, reverseWordDict, wordIndices

    
# Helper function for training skip-gram
# Returns training batch, corresponding labels, and the updated dataIndex placeholder

def createTrainingBatch(batchSize, numSkips, skipWindow, wordIndices, curWordIndex):

    # Validate parameters
    if batchSize % numSkips != 0:
        return -1

    if numSkips > 2 * skipWindow:
        return -1

    # Create two n-dimentional arrays for the training batch and the labels
    batch = numpy.ndarray(shape=(batchSize), dtype=numpy.int32)
    labels = numpy.ndarray(shape=(batchSize, 1), dtype=numpy.int32)

    # The span is the number of words from the beginning of the left skip window to the end of the right skip window
    span = 2 * skipWindow + 1

    # wordBuffer is a deque object of length span
    wordBuffer = collections.deque(maxlen=span)

    # Fill wordBuffer with word indices starting at wordIndex
    for i in range(span):
        wordBuffer.append(wordIndices[curWordIndex])
        curWordIndex += 1
        curWordIndex %= len(wordIndices)

    # Fill batch and labels n-dimensional arrays
    for i in range(batchSize // numSkips):

        # Initialize centerWordIndex to an invalid value before while loop
        # labelIndex is the index of the label (central word) in the span
        labelIndex = skipWindow
        avoidList = [labelIndex]

        for j in range(numSkips):

            # Randomly choose center word index
            while labelIndex in avoidList:
                labelIndex = random.randint(0, span - 1)

            avoidList.append(labelIndex)

            batch[i * numSkips + j] = wordBuffer[skipWindow]
            labels[i * numSkips + j, 0] = wordBuffer[labelIndex]

        # Update wordBuffer and curWordIndex
        wordBuffer.append(wordIndices[curWordIndex])
        curWordIndex += 1
        curWordIndex %= len(wordIndices)

    # Lower curWordIndex by span to make sure no words are skipped at the end of the batch
    curWordIndex -= span
    curWordIndex %= len(wordIndices)

    #print "wordBuffer:", wordBuffer
    
    return batch, labels, curWordIndex


# Visualize word embeddings

def plotWithLabels(lowDimensionEmbeddings, labels, filename='tsne.png'):

    # Return error if there are less labels than word embeddings
    if lowDimensionEmbeddings.shape[0] < len(labels):
        return -1   

    plt.figure(figsize=(18, 18))
    for i, label in enumerate(labels):
        x, y = lowDimensionEmbeddings[i, :]
        plt.scatter(x, y)
        plt.annotate(label, xy=(x, y), xytext=(5, 2), textcoords='offset points', ha='right', va='bottom')
        plt.savefig(filename)
    
    return


def main():
    
    wordCount, wordDict, reverseWordDict, wordIndices = createDictionary()
    
    batch, labels, curWordIndex = createTrainingBatch(8, 2, 10, wordIndices, 0)

    for i in range(8):
        print batch[i], reverseWordDict[batch[i]], '->', labels[i, 0], reverseWordDict[labels[i, 0]]

    # Skip-gram parameters
    batchSize = 128
    embeddingSize = 128
    skipWindow = 10
    numSkips = 2

    validationSize = 16
    validationWindow = 50
    numSampled = 64

    # Create an array of validtionSize random numbers between 0 and validationWindow - 1
    validationExamples = numpy.random.choice(validationWindow, validationSize, replace=False)
    
    graph = tensorflow.Graph()
    
    with graph.as_default():

        # Placeholders for inputs and labels tensors
        trainingInputs = tensorflow.placeholder(tensorflow.int32, shape=[batchSize])
        trainingLabels = tensorflow.placeholder(tensorflow.int32, shape=[batchSize, 1])

        # Constant tensor holding validationExamples
        validationDataset = tensorflow.constant(validationExamples, dtype=tensorflow.int32)
        
        with tensorflow.device('/cpu:0'):

            # Word embeddings tensor, contains random values between -1.0 and 1.0
            embeddings = tensorflow.Variable(tensorflow.random_uniform([VOCABULARY_SIZE, embeddingSize], -1.0, 1.0))

            # Look up vector for each source word in the batch 
            embed = tensorflow.nn.embedding_lookup(embeddings, trainingInputs)

            # Variables needed for computing Noise Contrastive Estimation loss
            nceWeights = tensorflow.Variable(tensorflow.truncated_normal([VOCABULARY_SIZE, embeddingSize], stddev=1.0 / math.sqrt(embeddingSize)))
            nceBiases = tensorflow.Variable(tensorflow.zeros([VOCABULARY_SIZE]))

            # Compute average NCE loss for batch
            nceLoss = tensorflow.reduce_mean(tensorflow.nn.nce_loss(weights=nceWeights, biases=nceBiases, labels=trainingLabels, inputs=embed, num_sampled=numSampled, num_classes=VOCABULARY_SIZE))

            # Create Stochastic Gradient Descent optimizer with learning rate of 1.0 
            sgdOptimizer = tensorflow.train.GradientDescentOptimizer(1.0).minimize(nceLoss)

            # Compute cosine similarity between minibatch examples and all word embeddinggs
            norm = tensorflow.sqrt(tensorflow.reduce_sum(tensorflow.square(embeddings), 1, keep_dims=True))
            normalizedEmbeddings = embeddings / norm
            validationEmbeddings = tensorflow.nn.embedding_lookup(normalizedEmbeddings, validationDataset)
            cosineSimilarity = tensorflow.matmul(validationEmbeddings, normalizedEmbeddings, transpose_b=True)

            # Initialize all tensorflow.Variable variables (embeddings, nceWeights, and nceBiase)
            init = tensorflow.global_variables_initializer()

    # Train skip-gram
    with tensorflow.Session(graph=graph) as session:

        init.run()

        avgLoss = 0

        for step in xrange(NUM_TRAINING_STEPS):

            batchInputs, batchLabels, curWordIndex = createTrainingBatch(batchSize, numSkips, skipWindow, wordIndices, curWordIndex)
            _, lossValue = session.run([sgdOptimizer, nceLoss], feed_dict={trainingInputs: batchInputs, trainingLabels: batchLabels})

            avgLoss += lossValue

            if step % 10000 == 0:

                similarity = cosineSimilarity.eval()

                for i in xrange(validationSize):

                    validationWord = reverseWordDict[validationExamples[i]]

                    kNearest = 8 # k nearest neighbors
                    nearest = (-similarity[i, :]).argsort()[1:kNearest + 1]
                    logStr = "Nearest to %s:" % validationWord, validationExamples[i]

                    for k in xrange(kNearest):

                        closeWord = reverseWordDict[nearest[k]]
                        logStr = "%s %s," % (logStr, closeWord)

                    print logStr

        finalEmbeddings = normalizedEmbeddings.eval()

    # Visualize embeddings
    tsne = TSNE(perplexity=30, n_components=2, init='pca', n_iter=5000)
    plotNum = 500
    lowDimensionEmbeddings = tsne.fit_transform(finalEmbeddings[:plotNum, :])
    labels = [reverseWordDict[i] for i in xrange(plotNum)]
    plotWithLabels(lowDimensionEmbeddings, labels)
            
    return

main()
    
