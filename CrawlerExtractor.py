from bs4 import BeautifulSoup
import urllib
import re
import requests

def visible(element):
    if element.parent.name in ['style', 'script', '[document]', 'head', 'title']:
        return False
    elif re.match('<!--.*-->', str(element.encode('utf-16'))):
        return False
    return True

def extract_data(link):
	file = open("Crawler_Output.txt","a")

	req = urllib.urlopen(link)
	soup = BeautifulSoup(req,"lxml")
	data = soup.findAll(text=True)
	result = filter(visible, data)
	file.write(str(result))

def main():
	
	my_link = ''
	temp = ''
	link_list = []

	url = raw_input("Enter a github URL: ")
	#url = "https://github.com/hshantanu/Entropy-Calculator/blob/master/Source.cpp"

	req  = requests.get(url)
	data = req.text
	soup = BeautifulSoup(data,"lxml")

	for link in soup.find_all('a'):	
		my_link = link.get('href')
		if 'http' in my_link:
			temp = my_link
		else:
			my_link = temp + my_link
		#print my_link
		link_list.append(my_link)

	link_list = link_list[1:]

	for val in link_list:
		print val
		extract_data(val)

main()