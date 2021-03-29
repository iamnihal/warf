from django.shortcuts import render
from .forms import SubdomainForm, DirectoryBruteForce, Waybackurls, JsFiles, JsLinks, JsSecrets, GithubSubdomainForm
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
global fullscanContext

def index(request):
    return render(request, 'testing/index.html')

#Subdomain Finder
def subdomain_finder(request):
    if request.method == 'POST':
        # sublisterForm = SubdomainForm()
        # githubForm = GithubSubdomainForm()
        subdomain = str(request.POST.get('subdomain', None))
        gitSubdomain = str(request.POST.get('github-subdomain', None))
        gitToken = str(request.POST.get('github-token', None))
        print(subdomain)
        print(gitSubdomain)
        print(gitToken)

        try:
            os.chdir('testing/')
            print("Directory Changed")
        except:
            pass

        if subdomain != "None":
            print("Inside Sublister")
            #Enable port scanning
            subdom = sublist3r.main(subdomain, 40, '{}_{}.txt'.format(subdomain,timestr), ports= None, silent=True, verbose= False, enable_bruteforce= False, engines=None)
            return render(request, 'testing/subdomain.html', {'subdom': subdom})
 

        print("Sublister Skipped")
        if gitSubdomain != "None":
            gitsubs = 'github_subs_{}.txt'.format(timestr)
            result = subprocess.run(["python","github-subdomains.py","-t",gitToken,"-d",gitSubdomain,], capture_output=True, text=True)

            gitsubs_list = []

            for line in result.stdout.splitlines():
                gitsubs_list.append(line)

            for item in gitsubs_list:
                print(item)
            
            # with open(gitsubs, 'a+') as write_gitsubs_file:
            #     for line in result.stdout:
            #         write_gitsubs_file.write(line + '\n')

        return render(request, 'testing/subdomain.html', {'subdom': gitsubs_list})
    else:
        sublisterForm = SubdomainForm()
        githubForm = GithubSubdomainForm() 
    return render(request, 'testing/subdomain-index.html')

#Directory Brute Force
def directory_brute_force(request):
    if request.method == 'POST':
        form = DirectoryBruteForce()
        directory = str(request.POST.get('directory'))
        print(directory)
        
        # try:
        #     os.chdir('testing/dirsearch/')
        # except:
        #     pass


        try:
            os.chdir('testing/')
        except:
            pass

        dirtimestr = time.strftime("%Y-%m-%d")
        report = 'report_{}.txt'.format(dirtimestr)
        print(report)
        directory_search = subprocess.run(["python","dirsearch/dirsearch.py","-u",directory,"-t","60","-w","dirsearch/robotsdis.txt","--plain-text-report",report], capture_output=True, text=True)
        print(directory_search.stdout)

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

#JS Secrets
#Need to verify live js links
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
        with open(js_secret_filename, 'a') as secret_file:
            for secrets in js_secrets_list:
                secret_file.write(secrets + '\n')

        return render(request, 'testing/secret.html', {'context':js_secrets_list})
    else:
        return render(request, 'testing/secret-index.html')

#LinkFinder
#Need to verify live js files
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

def full_scan(request):
    if request.method == 'POST':
        domain = str(request.POST.get('fullscan'))

        try:
            os.chdir('testing/')
            print("Directory Changed")
        except:
            pass

        #Enable port scanning
        output_subdomain = '{}.txt'.format(domain)
        subdom = sublist3r.main(domain, 40, output_subdomain, ports=None, silent=True, verbose= False, enable_bruteforce= False, engines=None)
        
        print("Subdomain enumeration Completed")
        # report = 'directory_report_{}.txt'.format(timestr)
        # print(report)
        directory_search = subprocess.run(["python","dirsearch/dirsearch.py","-l",output_subdomain,"--full-url","-q","-t","60","-w","dirsearch/robotsdis.txt"], capture_output=True, text=True)
        # print(directory_search.stdout)

        with open('bruteforce.txt', 'a') as brute_force:
            brute_force.writelines(directory_search.stdout)

        directory_list = []
        with open('bruteforce.txt', 'r') as r:
            for line in r:
                directory_list.append(line)


        # print(directory_list)
        status = []
        size = []
        directory_link = []

        for line in directory_list:
            item = line.split(' ')
            try:
                status.append(item[0])
            except IndexError:
                status.append("None")

            try:
                size.append(item[5])
            except IndexError:
                size.append("None")
            
            try:
                directory_link.append(item[7])
            except IndexError:
                directory_link.append("None")
        
        directory_brute_link = zip(directory_link, size, status)
        
        print("Directory Brute Force Completed")
        #Wayback URLs
        wayback_urls = requests.get('http://web.archive.org/cdx/search/cdx?url=*.{}/*&output=json&fl=original&collapse=urlkey&limit='.format(domain)).json()

        wayback_urls_list = []
        for link in wayback_urls:
            wayback_urls_list.append(link[0])

        unique_wayback_urls = set(wayback_urls_list)

        with open('{}_Wayback_URLs_{}.txt'.format(domain, timestr), 'a+') as write_wayback_urls:
            for url in unique_wayback_urls:
                write_wayback_urls.write(url + '\n')


        print("Wayback URLs Completed")
        #JavaScript URLs
        js_file_urls = []
        for link in wayback_urls:
            if re.search(r'\.js$', link[0]):
                js_file_urls.append(link[0])

        unique_js_file_urls = set(js_file_urls)

        with open('{}_JS_URLs_{}.txt'.format(domain, timestr), 'a+') as write_js_file:
            for url in unique_js_file_urls:
                write_js_file.write(url + '\n')
        
        print("JavaScript URLs Completed")
        #JS Secrets
        js_secrets_list = []

        for url in unique_js_file_urls:
            js_secrets = subprocess.run([sys.executable,"SecretFinder.py","-i",url,"-o", "cli"], stderr=subprocess.DEVNULL, stdout=subprocess.PIPE,text=True)
            if "->" in js_secrets.stdout:
                for item in js_secrets.stdout.splitlines():
                    js_secrets_list.append(item)

        js_secret_filename = '{}_JS_Secret_{}.txt'.format(domain,timestr)
        with open(js_secret_filename, 'a') as secret_file:
            for secrets in js_secrets_list:
                secret_file.write(secrets + '\n')

        print("JS Secrets Completed")

        #LinkFinder
        for js_link in unique_js_file_urls:
            result = subprocess.run([sys.executable, "linkfinder.py", "-i", js_link, "-o", "cli"], stderr=subprocess.DEVNULL, stdout=subprocess.PIPE,text=True)
            # print(result.stdout)
            if result.stdout:
                #This is not efficient. Need to store the result.stdout in list and then write it to the file.
                with open('jslinks.txt', 'w') as file:
                    if "Usage" in result.stdout:
                        pass
                    else:
                        file.write(result.stdout)
            else:
                continue

            js_links = []
            with open('jslinks.txt', 'r') as read_file:
                content = read_file.read().splitlines()
                for link in content:
                    js_links.append(link)
                
            unique_js_links = set(js_links)

        print("LinkFinder Completed")

        global fullscanContext

        fullscanContext = {
            'subdom':subdom,
            'directory_link': directory_link,
            'directory_size_status':directory_brute_link,
            'wayback_url':list(unique_wayback_urls),
            'js_url':list(unique_js_file_urls),
            'js_secrets':js_secrets_list,
            'js_link':list(unique_js_links)
        }
        
        print(fullscanContext)
        return render(request, 'testing/fullscan.html', {'context':fullscanContext})
    else:
        return render(request, 'testing/fullscan-index.html')

def fullscan_result(request):
    if request.method == 'GET':
        subdomain = request.GET['type']
        directory = request.GET.get('type', None)
        wayback = request.GET.get('type', None)
        jsurl = request.GET.get('type', None)
        secret = request.GET.get('type', None)
        link_finder = request.GET.get('type', None)

        if subdomain == "subdomain":
            print("Show subdomain page")
            sub_context = fullscanContext['subdom']
            return render(request, 'testing/fullscan-subdomain.html', {'context':sub_context})

        if directory == "directory":
            print("Show directory page")
            dir_context = fullscanContext['directory_size_status']
            return render(request, 'testing/fullscan-directory.html', {'context':dir_context})

        if wayback == "wayback":
            print("Show wayback page")
            wayback_context = fullscanContext['wayback_url']
            return render(request, 'testing/fullscan-wayback.html', {'context':wayback_context})

        if jsurl == "jsurl":
            print("Show JS url page")
            jsurl_context = fullscanContext['js_url']
            return render(request, 'testing/fullscan-jsurl.html', {'context':jsurl_context})

        if secret == "secrets":
            print("Show Secret page")
            secret_context = fullscanContext['js_secrets']
            return render(request, 'testing/fullscan-secret.html', {'context':secret_context})

        if link_finder == "linkfinder":
            print("Show Linkfinder page")
            linkfinder_context = fullscanContext['js_link']
            return render(request, 'testing/fullscan-jsurl.html', {'context':linkfinder_context})
        
        return render(request, 'testing/fullscan-result.html')
    else:
        return render(request, 'testing/fullscan.html')