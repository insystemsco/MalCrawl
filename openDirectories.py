import fnmatch
import os
import re

import tensorflow as tf

wordCounts = {}

for root, subFolders, fileNames in os.walk('/home/rj/Downloads/theZoo-master/malwares/Source/Original'):
    for fileName in fileNames:
        with open(os.path.join(root, fileName), 'r') as f:
            for lines in f:
                line = re.split('[^A-Za-z0-9]', lines)
                line = filter(None, line)
                print line
