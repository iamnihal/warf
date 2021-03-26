from django.shortcuts import render
from .forms import SubdomainForm, DirectoryBruteForce, Waybackurls, JsFiles, JsLinks, JsSecrets
from django.http import HttpResponse
from . import sublist3r
from .subbrute import subbrute
import subprocess
import os
import sys
import re
import requests
import time

timestr = time.strftime("%Y-%m-%d-%H-%M-%S")

def index(request):
    return render(request, 'testing/index.html')

#Subdomain Finder
def subdomain_finder(request):
    if request.method == 'POST':
        form = SubdomainForm()
        subdomain = str(request.POST.get('subdomain'))
        subdom = sublist3r.main(subdomain, 40, '{}_{}.txt'.format(subdomain,timestr), ports= None, silent=True, verbose= False, enable_bruteforce= False, engines=None)
        return render(request, 'testing/subdomain.html', {'subdom': subdom})
    else:
        form = SubdomainForm()
    return render(request, 'testing/subdomain-index.html')

#Directory Brute Force
def directory_brute_force(request):
    if request.method == 'POST':
        form = DirectoryBruteForce()
        directory = str(request.POST.get('directory'))
        print(directory)
        
        try:
            os.chdir('testing/dirsearch/')
        except:
            pass

        dirtimestr = time.strftime("%Y-%m-%d")
        report = 'report_{}.txt'.format(dirtimestr)
        directory_search = subprocess.run(["python","dirsearch.py","-u",directory,"-t","60","-w","robotsdis.txt","--plain-text-report",report], capture_output=True)

        with open(report, 'r') as write_directory_file:
            data = write_directory_file.readlines()[2:]

        status = []
        size = []
        directory_link = []

        for line in data:
            row = re.split(" +", line)
            status.append(row[0])
            size.append(row[1])
            directory_link.append(row[2])
        
        context = zip(directory_link, size, status)
        
        return render(request, 'testing/directory.html', {'context': context})
    else:
        form = DirectoryBruteForce()
    return render(request, 'testing/directory-index.html')

#Wayback URLs
def waybackurls(request):
    if request.method == 'POST':
        form = Waybackurls()
        domain = str(request.POST.get('wayback'))
        wayback_urls = requests.get('http://web.archive.org/cdx/search/cdx?url=*.{}/*&output=json&fl=original&collapse=urlkey&limit='.format(domain)).json()

        wayback_urls_list = []
        for link in wayback_urls:
            wayback_urls_list.append(link[0])

        unique_wayback_urls = set(wayback_urls_list)

        with open('{}_Wayback_URLs_{}.txt'.format(domain, timestr), 'a+') as write_wayback_urls:
            for url in unique_wayback_urls:
                write_wayback_urls.write(url + '\n')

        return render(request, 'testing/wayback.html', {'context': unique_wayback_urls})
    else:
        form = Waybackurls()
    return render(request, 'testing/wayback-index.html')

#JavaScript File URLs
def js_files(request):
    if request.method == 'POST':
        form = JsFiles()
        domain = str(request.POST.get('jsfile'))
        urls = requests.get('http://web.archive.org/cdx/search/cdx?url=*.{}/*&output=json&fl=original&collapse=urlkey'.format(domain)).json()

        js_file_urls = []
        for link in urls:
            if re.search(r'\.js$', link[0]):
                js_file_urls.append(link[0])

        unique_js_file_urls = set(js_file_urls)
        with open('{}_JS_URLs_{}.txt'.format(domain, timestr), 'a+') as write_js_file:
            for url in unique_js_file_urls:
                write_js_file.write(url + '\n')

        return render(request, 'testing/jsfile.html', {'context': unique_js_file_urls})
    else:
        form = JsFiles()
    return render(request, 'testing/jsfile-index.html')


def js_secrets(request):
    if request.method == 'POST':
        form = JsSecrets()
        domain = str(request.POST.get('secret'))
        urls = requests.get('http://web.archive.org/cdx/search/cdx?url=*.{}/*&output=json&fl=original&collapse=urlkey&limit='.format(domain)).json()

        js_file_urls = []
        for link in urls:
            if re.search(r'\.js$', link[0]):
                js_file_urls.append(link[0])

        unique_js_file_urls = set(js_file_urls)
        print(len(unique_js_file_urls))

        try:
            os.chdir('testing/')
        except:
            print("Directory is already Testing")

        js_secrets_list = []

        for url in unique_js_file_urls:
            js_secrets = subprocess.run([sys.executable,"SecretFinder.py","-i",url,"-o", "cli"], stderr=subprocess.DEVNULL, stdout=subprocess.PIPE,text=True)
            if "->" in js_secrets.stdout:
                for item in js_secrets.stdout.splitlines():
                    js_secrets_list.append(item)

        js_secret_filename = '{}_JS_Secret_{}.txt'.format(domain,timestr)
        with open(js_secret_filename, 'a+') as secret_file:
            for secrets in js_secrets_list:
                secret_file.write(secrets + '\n')

        return render(request, 'testing/secret.html', {'context':js_secrets_list})
    else:
        return render(request, 'testing/secret-index.html')


def js_links(request):
    if request.method == 'POST':
        form = JsLinks()
        domain = str(request.POST.get('endpoint'))

        urls = requests.get('http://web.archive.org/cdx/search/cdx?url=*.{}/*&output=json&fl=original&collapse=urlkey&limit='.format(domain)).json()

        js_file_urls = []
        for link in urls:
            if re.search(r'\.js$', link[0]):
                js_file_urls.append(link[0])

        unique_js_file_urls = set(js_file_urls)

        print(len(unique_js_file_urls))

        try:
            os.chdir('testing/')
        except:
            print("Directory is already Testing")

        js_urls = []
        for js_link in unique_js_file_urls:
            print(js_link)
            result = subprocess.run([sys.executable, "linkfinder.py", "-i", js_link, "-o", "cli"], stderr=subprocess.DEVNULL, stdout=subprocess.PIPE,text=True)
            if result.stdout:

                #This is not efficient. Need to store the result.stdout in list and then write it to the file.
                with open('../jslinks.txt', 'w') as file:
                    if "Usage" in result.stdout:
                        pass
                    else:
                        file.write(result.stdout)

            js_links = []
            with open('../jslinks.txt', 'r') as read_file:
                content = read_file.read().splitlines()
                for link in content:
                    # if re.search(r'\.png$ | \.jpg$ | \.svg$ | \.woff$ | \.woff2$ | \.gif$ | \.jpeg$', link):
                    #     pass
                    # else:
                    js_links.append(link)
                
            unique_js_links = set(js_links)

        return render(request, 'testing/endpoint.html', {'context': unique_js_links})
    else:
        form = JsLinks()
    return render(request, 'testing/endpoint-index.html')