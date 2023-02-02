#!/usr/local/bin/python3

# Author: Jason Brewer
# Purpose: To identify Windows Functions that have a 'Caution' warning because these functions may degrade the security of the application
# Version: 1.0.1

from gevent import monkey as monk
monk.patch_all(thread=False,select=False)

import requests
import re
import argparse
import grequests
import emoji
from bs4 import BeautifulSoup
from time import sleep
from os import system


class Fetch:


	# Loads the header file and fuctions into a list
	def loadDataAPI(self,headers,function,threads):
	
		funcs = []
		with open(function, 'r') as fc:
			for f in fc.readlines():
				func = f.strip('\n').rstrip().lower()
				funcs.append(func)
	
	
		heads = []
		with open(headers, 'r') as h:
			for hd in h.readlines():
				head = hd.strip('\n').rstrip()
				heads.append(head)
	
	
		sites = []
		for f in funcs:
			for h in heads:
				sites.append(h.replace(".h","")+" "+f)	

		return sites


	def loadDataRunTime(self, function):

		funcs = []
		with open(function, 'r') as fc:
			for f in fc.readlines():
				func = f.strip('\n').rstrip().lower()
				funcs.append(func)

		return funcs


	# Exception Handler
	def exception(self, request, exception):
		print("\n[!!!] Error: {}: {} [!!!]\n".format(request.url,exception))
	

	def carveOut(self, function):

		defaultUpper = "carvedOutUpperCaseSymbols.txt"
		defaultOther = "carvedOutSymbolsWithNoUnderScore.txt"
		defaultUnder = "carvedOutSymbolsWithUnderScore.txt"	
		cmdUpper = "cat {} | grep 0x | cut -d' ' -f4 | grep \"^[A-Z]\" > {}".format(function,defaultUpper)
		cmdOther = "cat {} | grep 0x | cut -d' ' -f4 | grep -v \"^[A-Z]\" | grep -v \"^_\" > {}".format(function,defaultOther)
		cmdUnder = "cat {} | grep 0x | cut -d' ' -f4 | grep \"^_\" > {}".format(function,defaultUnder)
		system(cmdUpper)		
		system(cmdOther)		
		system(cmdUnder)
		print("\n[+] Files created with carved out symbols:\n\n\t -> {}\n\t -> {}\n\t -> {}\n".format(defaultUpper,defaultOther,defaultUnder))

		
	# Get Request for each header/function
	# Iterates through in a loop and adds each unique function and url to a set()
	def sendingAPI(self,headers,function,threads):		

		res = Fetch().loadDataAPI(headers,function,threads)
		numOfSites = set()
		func = set()
		for site in res:
			newSite = site.split(" ")	
			url = "https://learn.microsoft.com/en-us/windows/win32/api/{}".format(newSite[0])
			func.add(newSite[1])
			numOfSites.add(url)

			

		# Handles parsing out characters when using set() 
		for site in numOfSites:
			sites = site.replace("[","")
			sites = site.replace("'","")
			sites = site.replace("]","")
			numOfSites.add(sites)

		# Breaking down header file into smaller chunks. Header file consists of 976 individual headers.
		chunk1 = list(numOfSites)[:200]
		chunk2 = list(numOfSites)[200:400] 
		chunk3 = list(numOfSites)[400:600] 
		chunk4 = list(numOfSites)[600:800] 
		chunk5 = list(numOfSites)[800:] 


		# Added a timer between requests so threads are cleared
		page = grequests.map((grequests.get(site) for site in chunk1), exception_handler=self.exception, size=threads)
		sleep(2)
		page += grequests.map((grequests.get(site) for site in chunk2), exception_handler=self.exception, size=threads)
		sleep(2)
		page += grequests.map((grequests.get(site) for site in chunk3), exception_handler=self.exception, size=threads)
		sleep(2)
		page += grequests.map((grequests.get(site) for site in chunk4), exception_handler=self.exception, size=threads)
		sleep(2)
		page += grequests.map((grequests.get(site) for site in chunk5), exception_handler=self.exception, size=threads)

		seen = set()
		for f in func:
			for s in page:
				content = BeautifulSoup(s.content, "html.parser")
				results = re.findall(r'/en-us/windows/win32/api/\w+/[\w\-]+[\w\-]'+f,str(content))
				if len(results) != 0:
					seen.add(str(results))
				else:
					pass
		
		sleep(4)

		# Loop through seen set() for warnings in html
		for sn in seen:
			url = "https://learn.microsoft.com/"+sn
			url = url.replace("[","")
			url = url.replace("'","")
			url = url.replace("]","")
			newUrl = url.split('-')[-1]
			newPage = requests.get(url.strip('\n'))
			newContent = BeautifulSoup(newPage.content, "html.parser")
			newPattern = "Caution"
			altPattern = "More secure versions"
			alt2Pattern = "More-secure versions"
			newAltPattern = "Do not use"
			newResults = re.findall(newPattern,str(newContent))
			newAltResults = re.findall(altPattern,str(newContent))
			newAlt2Results = re.findall(newAltPattern,str(newContent))
			Alt2Results = re.findall(alt2Pattern,str(content))
			if 'Caution' in newResults:
				print("\n " + emoji.emojize(':warning: ' + ' ' + newUrl.upper() + emoji.emojize(' :warning: ') + " has a CAUTION warning when choosing to use it\n"))
			elif 'More secure versions' in newAltResults:
				print("\n " + emoji.emojize(':double_exclamation_mark: ' + ' ' + newUrl.upper() + emoji.emojize(' :double_exclamation_mark: ') + " has a MORE SECURE VERSION warning when choosing to use it\n"))
			elif 'More-secure versions' in Alt2Results:
				print("\n " + emoji.emojize(':double_exclamation_mark: ' + ' ' + newUrl.upper() + emoji.emojize(' :double_exclamation_mark: ') + " has a MORE SECURE VERSION warning when choosing to use it\n"))
			elif 'Do not use' in newAlt2Results:
				print("\n " + emoji.emojize(':police_car_light: ' + ' ' + newUrl.upper() + emoji.emojize(' :police_car_light: ')+ " has a DO NOT USE warning when choosing to use it\n"))
			else:
				pass


	def sendingRunTime(self,function,threads):

		newRes = Fetch().loadDataRunTime(function)
		numOfSites = set()
		func = set()
		for site in newRes:
			#newSite = site.replace('/-','/')
			#newSite = site.split('/')[-1]
			url = "https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/{}".format(site)
			func.add(site)
			numOfSites.add(url)
				

		# Handles parsing out characters when using set() 
		for site in numOfSites:
			sites = site.replace("[","")
			sites = site.replace("'","")
			sites = site.replace("]","")
			numOfSites.add(sites)


		# Breaking down header file into smaller chunks. Header file consists of 976 individual headers.
		chunk1 = list(numOfSites)[:200]
		chunk2 = list(numOfSites)[200:400] 
		chunk3 = list(numOfSites)[400:600] 
		chunk4 = list(numOfSites)[600:800] 
		chunk5 = list(numOfSites)[800:] 


		# Added a timer between requests so threads are cleared
		page = grequests.map((grequests.get(site) for site in chunk1), exception_handler=self.exception, size=threads)
		sleep(2)
		page += grequests.map((grequests.get(site) for site in chunk2), exception_handler=self.exception, size=threads)
		sleep(2)
		page += grequests.map((grequests.get(site) for site in chunk3), exception_handler=self.exception, size=threads)
		sleep(2)
		page += grequests.map((grequests.get(site) for site in chunk4), exception_handler=self.exception, size=threads)
		sleep(2)
		page += grequests.map((grequests.get(site) for site in chunk5), exception_handler=self.exception, size=threads)

		seen = set()
		content = set()
		for s in page:
			parse = BeautifulSoup(s.content, "html.parser")
			content.add(parse)


		for f in func:

			results = re.findall(r'/en-us/cpp/c-runtime-library/reference/'+f,str(content))
			if len(results) != 0:
				seen.add(str(results))
			else:
				pass


		# Loop through seen set() for warnings in html
		for sn in seen:
			url = "https://learn.microsoft.com/"+sn.split(',')[-1]
			url = url.replace("[","")
			url = url.replace("'","")
			url = url.replace("]","")
			url = url.replace(" ","")
			newPage = requests.get(url)
			newContent = BeautifulSoup(newPage.content, "html.parser")
			newPattern = "Caution"
			altPattern = "More secure versions"
			alt2Pattern = "More-secure versions"
			newAltPattern = "Do not use"
			newResults = re.findall(newPattern,str(newContent))
			newAltResults = re.findall(altPattern,str(newContent))
			Alt2Results = re.findall(alt2Pattern,str(newContent))
			newAlt2Results = re.findall(newAltPattern,str(newContent))
			if 'Caution' in newResults:
				print("\n " + emoji.emojize(':warning: ' + url.split('/')[-1].upper() + emoji.emojize(' :warining: ')+ " has a CAUTION warning when choosing to use it\n"))
			elif 'More secure versions' in newAltResults:
				print("\n " + emoji.emojize(':double_exclamation_mark: ' + ' ' + url.split('/')[-1].upper() + emoji.emojize(' :double_exclamation_mark: ')+ " has a MORE SECURE VERSION warning when choosing to use it\n"))
			elif 'More-secure versions' in Alt2Results:
				print("\n " + emoji.emojize(':double_exclamation_mark: ' + ' ' + url.split('/')[-1].upper() + emoji.emojize(' :double_exclamation_mark: ')+ " has a MORE SECURE VERSION warning when choosing to use it\n"))
			elif 'Do not use' in newAlt2Results:
				print("\n " + emoji.emojize(':police_car_light: ' + url.split('/')[-1].upper() + emoji.emojize(' :police_car_light:')+" has a DO NOT USE warning when choosing to use it\n"))
			else:
				pass


def main():

	parser = argparse.ArgumentParser(description='This program searches through all Windows Win32 Header files and parses the resulting content to see if a function has the word \'Caution\' when using it')
	parser.add_argument('-H', dest='headerFile', help='Supply a file containing all win32 headers')
	parser.add_argument('-c', dest='carveout', help='Parse out symbols from the output of the getPEinfo.py program')
	parser.add_argument('-f', dest='function', help='Supply a file containing a list of Windows functions')
	parser.add_argument('-r', dest='runtime', help='Supply a file containing a list of c-runtime functions')
	parser.add_argument('-sym', choices=['api','run'], dest='type', help='Use this flag when specifying whether the symbols (functions) are from C runtime library or Win32 API')
	parser.add_argument('-t', dest='threads', type=int, default=20, help='Supply the number of threads to run: Default is 20')
	args = parser.parse_args()

	if args.headerFile and args.function and args.type == 'api':
		headers = args.headerFile
		function = args.function
		threads = args.threads

		sendIt = Fetch().sendingAPI(headers,function, threads)
		sendIt

	if args.runtime and args.type == 'run':
		function = args.runtime
		threads = args.threads	
		sendIt = Fetch().sendingRunTime(function,threads)
		sendIt

	if args.carveout:
		function = args.carveout
		sendIt = Fetch().carveOut(function)
		sendIt

if __name__ == '__main__':
	try:
	       main()
	except KeyboardInterrupt:
		print("\n[---] User pressed CTRL-C [---]\n")
		exit()
