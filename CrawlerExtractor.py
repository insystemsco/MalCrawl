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
	r = urllib.urlopen(link)
	soup = BeautifulSoup(r,"lxml")
	data = soup.findAll(text=True)
	result = filter(visible, data)
	print result

def main():
	#url = raw_input("Enter a website to extract the URL's from: ")
	
	my_link = ''
	temp = ''
	link_list = []
	
	url = raw_input("Enter a github URL: ")

	req  = requests.get("http://" + url)
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
		extract_data(val)

main()