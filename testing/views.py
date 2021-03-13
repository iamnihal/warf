from django.shortcuts import render
from .forms import SubdomainForm, DirectoryBruteForce
from django.http import HttpResponse
from . import sublist3r
from .subbrute import subbrute
import subprocess
import os
import json
import re

def testing(request):
    if request.method == 'POST':
        form = SubdomainForm()
        subdomain = str(request.POST.get('subdomains'))
        subdom = sublist3r.main(subdomain, 40, '{}.txt'.format(subdomain), ports= None, silent=True, verbose= False, enable_bruteforce= False, engines=None)
        return render(request, 'testing/index.html', {'subdom': subdom})
    else:
        form = SubdomainForm()
    return render(request, 'testing/form.html')


def directory_brute_force(request):
    if request.method == 'POST':
        form = DirectoryBruteForce()
        directory = str(request.POST.get('directory'))
        print(directory)
        testdir = os.chdir('testing/dirsearch/')
        directory_search = subprocess.run(["python","dirsearch.py","-u",directory,"-w","common.txt", "--plain-text-report", "report.txt"], capture_output=True)

        with open('report.txt', 'r') as report_file:
            data = report_file.readlines()[2:]

        status = []
        size = []
        directory_link = []

        for line in data:
            row = re.split(" +", line)
            status.append(row[0])
            size.append(row[1])
            directory_link.append(row[2])
        
        print(status)
        print(size)
        print(directory_link)
        context = zip(directory_link, size, status)
        

        return render(request, 'testing/directory.html', {'context': context})
    else:
        return render(request, 'testing/directory.html')