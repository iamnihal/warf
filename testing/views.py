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

timestr = time.strftime("%Y-%m-%d-%H-%M")
# global fullscanContext

def index(request):
    return render(request, 'testing/index.html')

def download_result(request):
    if request.method == 'GET':
        subdomain = request.GET.get('scan', None)
        directory = request.GET.get('scan', None)
        wayback = request.GET.get('scan', None)
        jsurl = request.GET.get('scan', None)
        secret = request.GET.get('scan', None)
        link_finder = request.GET.get('scan', None)

        if subdomain == "subdomain":
            output_file = f'/home/nihal/fwapf/testing/{subdomain_output_file}'
            filename = f'{subdomain_output_file}.txt'
            with open(output_file, 'r') as fh:
                response = HttpResponse(fh.read(), content_type="text/html")
                response['Content-Disposition'] = "attachment; filename=%s" % filename
                return response

        if directory == "directory":
            output_file = f'/home/nihal/fwapf/testing/{directory_output_file}'
            filename = f'{directory_output_file}.txt'
            with open(output_file, 'r') as fh:
                response = HttpResponse(fh.read(), content_type="text/html")
                response['Content-Disposition'] = "attachment; filename=%s" % filename
                return response

        if wayback == "wayback":
            output_file = f'/home/nihal/fwapf/testing/{wayback_output_file}'
            filename = f'{wayback_output_file}.txt'
            with open(output_file, 'r') as fh:
                response = HttpResponse(fh.read(), content_type="text/html")
                response['Content-Disposition'] = "attachment; filename=%s" % filename
                return response

        if jsurl == "jsurl":
            output_file = f'/home/nihal/fwapf/testing/{jsurl_output_file}'
            filename = f'{jsurl_output_file}.txt'
            with open(output_file, 'r') as fh:
                response = HttpResponse(fh.read(), content_type="text/html")
                response['Content-Disposition'] = "attachment; filename=%s" % filename
                return response

        if secret == "secret":
            output_file = f'/home/nihal/fwapf/testing/{secret_output_file}'
            filename = f'{secret_output_file}.txt'
            with open(output_file, 'r') as fh:
                response = HttpResponse(fh.read(), content_type="text/html")
                response['Content-Disposition'] = "attachment; filename=%s" % filename
                return response

        if link_finder == "linkfinder":
            output_file = f'/home/nihal/fwapf/testing/{linkfinder_output_file}'
            filename = f'{linkfinder_output_file}.txt'
            with open(output_file, 'r') as fh:
                response = HttpResponse(fh.read(), content_type="text/html")
                response['Content-Disposition'] = "attachment; filename=%s" % filename
                return response
    else:
        return render(request, 'testing/index.html')

#Subdomain Finder
def subdomain_finder(request):
    if request.method == 'POST':
        subdomain = str(request.POST.get('subdomain', None))
        gitSubdomain = str(request.POST.get('github-subdomain', None))
        gitToken = str(request.POST.get('github-token', None))

        try:
            os.chdir('testing/')
            print("Directory Changed")
        except:
            pass

        if subdomain != "None":
            print("Inside Sublister")
            global subdomain_output_file
            subdomain_output_file = '{}_{}.txt'.format(subdomain,timestr)
            #Enable port scanning
            subdom = sublist3r.main(subdomain, 40, subdomain_output_file, ports= None, silent=True, verbose= False, enable_bruteforce= False, engines=None)
            return render(request, 'testing/subdomain.html', {'subdom': subdom})
 

        print("Sublister Skipped")
        if gitSubdomain != "None":
            global gitsubs
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

        global directory_output_file
        directory_output_file = 'Directory_{}.txt'.format(timestr)
        directory_search = subprocess.run(["python","dirsearch/dirsearch.py","-u",directory,"-t","60","-w","dirsearch/robotsdis.txt","--plain-text-report",directory_output_file], capture_output=True, text=True)

        with open(directory_output_file, 'r') as write_directory_file:
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

        try:
            os.chdir('testing/')
        except:
            pass

        global wayback_output_file
        wayback_output_file = '{}_Wayback_URLs_{}.txt'.format(domain, timestr)
        with open(wayback_output_file, 'a+') as write_wayback_urls:
            for url in unique_wayback_urls:
                write_wayback_urls.write(url + '\n')

        return render(request, 'testing/wayback.html', {'context': unique_wayback_urls})
    else:
        form = Waybackurls()
    return render(request, 'testing/wayback-index.html')

#JavaScript URLs
def js_urls(request):
    if request.method == 'POST':
        form = JsFiles()
        domain = str(request.POST.get('jsurl'))
        urls = requests.get('http://web.archive.org/cdx/search/cdx?url=*.{}/*&output=json&fl=original&collapse=urlkey'.format(domain)).json()

        js_file_urls = []
        for link in urls:
            if re.search(r'\.js$', link[0]):
                js_file_urls.append(link[0])

        unique_js_file_urls = set(js_file_urls)

        global jsurl_output_file
        jsurl_output_file = '{}_JS_URLs_{}.txt'.format(domain, timestr)
        with open(jsurl_output_file, 'a+') as write_js_file:
            for url in unique_js_file_urls:
                write_js_file.write(url + '\n')

        return render(request, 'testing/jsurl.html', {'context': unique_js_file_urls})
    else:
        form = JsFiles()
    return render(request, 'testing/jsurl-index.html')

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

        

        global secret_output_file
        secret_output_file = '{}_JS_Secret_{}.txt'.format(domain,timestr)
        with open(secret_output_file, 'a') as secret_file:
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
            result = subprocess.run([sys.executable, "linkfinder.py", "-i", js_link, "-o", "cli"], stderr=subprocess.DEVNULL, stdout=subprocess.PIPE,text=True)
            if result.stdout:
                if "Usage" in result.stdout:
                    pass
                else:
                    for item in result.stdout.splitlines():
                        js_urls.append(item)
            
        global linkfinder_output_file
        linkfinder_output_file = '{}_Linkfinder_{}.txt'.format(domain, timestr)

        with open(linkfinder_output_file, 'a') as write_linkfinder_output:
            for line in js_urls:
                write_linkfinder_output.write(line + '\n')

        unique_js_links = set(js_urls)

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
        global subdomain_output_file
        subdomain_output_file = '{}_{}.txt'.format(domain,timestr)
        subdom = sublist3r.main(domain, 40, subdomain_output_file, ports=None, silent=True, verbose= False, enable_bruteforce= False, engines=None)
        
        print("Subdomain enumeration Completed")
        
        directory_search = subprocess.run(["python","dirsearch/dirsearch.py","-l",subdomain_output_file,"--full-url","-q","-t","60","-w","dirsearch/robotsdis.txt"], capture_output=True, text=True)

        global directory_output_file
        directory_output_file = 'Directory_{}.txt'.format(timestr)

        with open(directory_output_file, 'a') as write_directory_output:
            write_directory_output.writelines(directory_search.stdout)

        directory_list = []
        with open(directory_output_file, 'r') as r:
            for line in r:
                directory_list.append(line)

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

        global wayback_output_file
        wayback_output_file = '{}_Wayback_URLs_{}.txt'.format(domain, timestr)

        with open(wayback_output_file, 'a') as write_wayback_output:
            for url in unique_wayback_urls:
                write_wayback_output.write(url + '\n')


        print("Wayback URLs Completed")
        #JavaScript URLs
        js_file_urls = []
        for link in wayback_urls:
            if re.search(r'\.js$', link[0]):
                js_file_urls.append(link[0])

        unique_js_file_urls = set(js_file_urls)

        global jsurl_output_file
        jsurl_output_file = '{}_JS_URLs_{}.txt'.format(domain, timestr)

        with open(jsurl_output_file, 'a') as write_jsurl_output:
            for url in unique_js_file_urls:
                write_jsurl_output.write(url + '\n')
        
        print("JavaScript URLs Completed")
        #JS Secrets
        js_secrets_list = []

        for url in unique_js_file_urls:
            js_secrets = subprocess.run([sys.executable,"SecretFinder.py","-i",url,"-o", "cli"], stderr=subprocess.DEVNULL, stdout=subprocess.PIPE,text=True)
            if "->" in js_secrets.stdout:
                for item in js_secrets.stdout.splitlines():
                    js_secrets_list.append(item)

        global secret_output_file
        secret_output_file = '{}_JS_Secret_{}.txt'.format(domain,timestr)

        with open(secret_output_file, 'a') as write_secret_output:
            for secrets in js_secrets_list:
                write_secret_output.write(secrets + '\n')

        print("JS Secrets Completed")

        #LinkFinder
        jsurls = []
        for js_link in unique_js_file_urls:
            result = subprocess.run([sys.executable, "linkfinder.py", "-i", js_link, "-o", "cli"], stderr=subprocess.DEVNULL, stdout=subprocess.PIPE,text=True)
            if result.stdout:
                if "Usage" in result.stdout:
                    pass
                else:
                    for item in result.stdout.splitlines():
                        jsurls.append(item)
            
        global linkfinder_output_file
        linkfinder_output_file = '{}_Linkfinder_{}.txt'.format(domain, timestr)

        with open(linkfinder_output_file, 'a') as write_linkfinder_output:
            for line in jsurls:
                write_linkfinder_output.write(line + '\n')

        unique_js_links = set(jsurls)

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
        
        return render(request, 'testing/fullscan-overview.html', {'context':fullscanContext})
    else:
        return render(request, 'testing/fullscan-index.html')

def fullscan_result(request):
    if request.method == 'GET':
        subdomain = request.GET.get('type', None)
        directory = request.GET.get('type', None)
        wayback = request.GET.get('type', None)
        jsurl = request.GET.get('type', None)
        secret = request.GET.get('type', None)
        link_finder = request.GET.get('type', None)

        if subdomain == "subdomain":
            sub_context = fullscanContext['subdom']
            return render(request, 'testing/fullscan-result.html', {'subdomain_context':sub_context})

        if directory == "directory":
            dir_context = fullscanContext['directory_size_status']
            return render(request, 'testing/fullscan-result.html', {'directory_context':dir_context})

        if wayback == "wayback":
            wayback_context = fullscanContext['wayback_url']
            return render(request, 'testing/fullscan-result.html', {'wayback_context':wayback_context})

        if jsurl == "jsurl":
            jsurl_context = fullscanContext['js_url']
            return render(request, 'testing/fullscan-result.html', {'jsurl_context':jsurl_context})

        if secret == "secrets":
            secret_context = fullscanContext['js_secrets']
            return render(request, 'testing/fullscan-result.html', {'secret_context':secret_context})

        if link_finder == "linkfinder":
            linkfinder_context = fullscanContext['js_link']
            return render(request, 'testing/fullscan-result.html', {'linkfinder_context':linkfinder_context})
        
        return render(request, 'testing/fullscan-result.html')
    else:
        return render(request, 'testing/fullscan.html')