from django.shortcuts import render
from django.http import HttpResponse
from django.contrib import messages
from django.urls import reverse
from . import sublist3r
from .subbrute import subbrute
from background_task import background
import subprocess
import os
import sys
import re
import requests
import time
from .forms import (
    SubdomainForm,
    DirectoryBruteForce,
    Waybackurls,
    JsFiles,
    JsLinks,
    JsSecrets,
    GithubSubdomainForm,
)


timestr = time.strftime("%Y-%m-%d-%H-%M")
subdomain_output_file = "Null"
directory_output_file = "Null"
wayback_output_file = "Null"
jsurl_output_file = "Null"
secret_output_file = "Null"
linkfinder_output_file = "Null"


def index(request):
    return render(request, "testing/index.html")
    

def handle_uploaded_file(f):
    global wordlist_name
    wordlist_name = f'{os.path.splitext(f.name)[0]}-{time.strftime("%M-%S")}.txt'
    print(wordlist_name)
    with open("testing/wordlist/" + wordlist_name, "ab+") as destination:
        for chunk in f.chunks():
            destination.write(chunk)


def setting_wordlist(request):
    if request.method == "POST":
        filename = request.FILES["myfile"].name
        if os.path.splitext(filename)[1] == ".txt":
            if request.FILES["myfile"].content_type == "text/plain":
                handle_uploaded_file(request.FILES["myfile"])
                messages.success(
                    request, f"File uploaded successfully as {wordlist_name}"
                )
            else:
                messages.success(request, "Please upload a valid TXT file!!")
        else:
            messages.success(request, "Please upload a valid TXT file!!")
    return render(request, "testing/wordlist.html")


# AJAX Call
def ajax_call(request):
    scan = request.GET.get("scan", None)
    if scan == "subdomain":
        output_file = subdomain_output_file
    if scan == "directory":
        output_file = directory_output_file
    if scan == "wayback":
        output_file = wayback_output_file
    if scan == "jsurl":
        output_file = jsurl_output_file
    if scan == "secret":
        output_file = secret_output_file
    if scan == "linkfinder":
        output_file = linkfinder_output_file

    try:
        if os.path.exists(output_file):
            if os.stat(output_file).st_size != 0:
                with open(output_file, "r") as write_file:
                    data = write_file.readlines()[2:]
                data_json = {"data": data}
                return JsonResponse(data_json, safe=False)
            else:
                return HttpResponse("FileContentisZero")
        else:
            return HttpResponse("FileDoesNotExist")
            print("FileDoesNotExist")
    except FileNotFoundError:
        return HttpResponse("FileDoesNotExist")
    except NameError:
        print("NameError")
        return HttpResponse("FileNotFound")
    except ValueError:
        return HttpResponse("ValueError")


# Subdomain Finder
@background(schedule=1)
def subdomain_finder_task(subdomain, gitSubdomain, gitToken):
    print("Inside Subdomain Task")

    try:
        os.chdir("testing/")
        print("Directory Changed")
    except:
        pass

    if subdomain != "None":
        global subdomain_output_file
        subdomain_output_file = "{}_{}.txt".format(subdomain, timestr)
        # Enable port scanning
        subdom = sublist3r.main(
            subdomain,
            40,
            subdomain_output_file,
            ports=None,
            silent=True,
            verbose=False,
            enable_bruteforce=False,
            engines=None,
        )
        # return render(request, 'testing/subdomain.html', {'subdom': subdom})
        context = {"subdom": subdom}
        return context

    if gitSubdomain != "None":
        gitsubs = "github_subs_{}.txt".format(timestr)
        result = subprocess.run(
            [
                "python",
                "github-subdomains.py",
                "-t",
                gitToken,
                "-d",
                gitSubdomain,
            ],
            capture_output=True,
            text=True,
        )

        gitsubs_list = []

        for line in result.stdout.splitlines():
            gitsubs_list.append(line)

        with open(gitsubs, "a+") as write_gitsubs_file:
            for line in result.stdout:
                write_gitsubs_file.write(line + "\n")

        context = {"subdom": gitsubs_list}
        return context


def subdomain_finder(request):
    if request.method == "POST":
        subdomain = str(request.POST.get("subdomain", None))
        gitSubdomain = str(request.POST.get("github-subdomain", None))
        gitToken = str(request.POST.get("github-token", None))
        global sub_context
        sub_context = subdomain_finder_task.now(subdomain, gitSubdomain, gitToken)
        return render(request, "testing/subdomain.html", sub_context)
    else:
        return render(request, "testing/subdomain-index.html")


# Directory Brute Force
@background(schedule=1)
def directory_brute_force_task(directory):
    try:
        os.chdir("testing/")
    except:
        pass

    global directory_output_file
    directory_output_file = "Directory_{}.txt".format(timestr)

    if dir_wordlist == "on":
        os.chdir("./wordlist")
        files = sorted(os.listdir(os.getcwd()), key=os.path.getmtime)
        wordlist_file = files[-1]
        os.chdir("../")
        directory_search = subprocess.run(
            [
                "python",
                "dirsearch/dirsearch.py",
                "-u",
                directory,
                "-t",
                "60",
                "-w",
                f"wordlist/{wordlist_file}",
                "--plain-text-report",
                directory_output_file,
            ],
            capture_output=True,
            text=True,
        )
    else:
        directory_search = subprocess.run(
            [
                "python",
                "dirsearch/dirsearch.py",
                "-u",
                directory,
                "-t",
                "60",
                "-w",
                "dirsearch/robotsdis.txt",
                "--plain-text-report",
                directory_output_file,
            ],
            capture_output=True,
            text=True,
        )

    with open(directory_output_file, "r") as write_directory_file:
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
    return context


def directory_brute_force(request):
    if request.method == "POST":
        directory = str(request.POST.get("directory"))
        global dir_wordlist
        dir_wordlist = request.POST.get("wordlist")
        global dir_context
        dir_context = directory_brute_force_task.now(directory)

        return render(request, "testing/directory.html", {"context": dir_context})
    else:
        # try:
        #     if os.path.exists(directory_output_file):
        #         print("Deleting File")
        #         os.remove(directory_output_file)
        # except TypeError:
        #     print("The file does not exist")
        return render(request, "testing/directory-index.html")


# Wayback URLs
@background(schedule=1)
def waybackurls_task(domain):

    wayback_urls = requests.get(
        "http://web.archive.org/cdx/search/cdx?url=*.{}/*&output=json&fl=original&collapse=urlkey&limit=".format(
            domain
        )
    ).json()
    wayback_urls_list = []
    for link in wayback_urls:
        wayback_urls_list.append(link[0])

    unique_wayback_urls = set(wayback_urls_list)

    try:
        os.chdir("testing/")
    except:
        pass

    global wayback_output_file
    wayback_output_file = "{}_Wayback_URLs_{}.txt".format(domain, timestr)
    with open(wayback_output_file, "a+") as write_wayback_urls:
        for url in unique_wayback_urls:
            write_wayback_urls.write(url + "\n")

    context = {"context": unique_wayback_urls}
    return context


def waybackurls(request):
    if request.method == "POST":
        form = Waybackurls()
        domain = str(request.POST.get("wayback"))
        context = waybackurls_task.now(domain)
        return render(request, "testing/wayback.html", context)
    else:
        form = Waybackurls()
    return render(request, "testing/wayback-index.html")


# JavaScript URLs
@background(schedule=1)
def js_urls_task(domain):
    urls = requests.get(
        "http://web.archive.org/cdx/search/cdx?url=*.{}/*&output=json&fl=original&collapse=urlkey".format(
            domain
        )
    ).json()
    js_file_urls = []

    for link in urls:
        if re.search(r"\.js$", link[0]):
            js_file_urls.append(link[0])

    unique_js_file_urls = set(js_file_urls)

    try:
        os.chdir("testing/")
    except:
        pass

    global jsurl_output_file
    jsurl_output_file = "{}_JS_URLs_{}.txt".format(domain, timestr)

    with open(jsurl_output_file, "a+") as write_js_file:
        for url in unique_js_file_urls:
            write_js_file.write(url + "\n")

    context = {"context": unique_js_file_urls}
    return context


def js_urls(request):
    if request.method == "POST":
        form = JsFiles()
        domain = str(request.POST.get("jsurl"))
        urls = requests.get(
            "http://web.archive.org/cdx/search/cdx?url=*.{}/*&output=json&fl=original&collapse=urlkey".format(
                domain
            )
        ).json()
        context = js_urls_task.now(domain)
        return render(request, "testing/jsurl.html", context)
    else:
        form = JsFiles()
    return render(request, "testing/jsurl-index.html")


# JS Secrets
# Need to verify live js links
@background(schedule=1)
def js_secrets_task(domain):
    try:
        os.chdir("testing/")
    except:
        print("Directory is already Testing")

    urls = requests.get(
        "http://web.archive.org/cdx/search/cdx?url=*.{}/*&output=json&fl=original&collapse=urlkey&limit=".format(
            domain
        )
    ).json()
    js_file_urls = []

    for link in urls:
        if re.search(r"\.js$", link[0]):
            js_file_urls.append(link[0])

    unique_js_file_urls = set(js_file_urls)
    js_secrets_list = []

    for url in unique_js_file_urls:
        js_secrets = subprocess.run(
            [sys.executable, "SecretFinder.py", "-i", url, "-o", "cli"],
            stderr=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            text=True,
        )
        if "->" in js_secrets.stdout:
            for item in js_secrets.stdout.splitlines():
                js_secrets_list.append(item)

    global secret_output_file
    secret_output_file = "{}_JS_Secret_{}.txt".format(domain, timestr)

    with open(secret_output_file, "a+") as secret_file:
        for secrets in js_secrets_list:
            secret_file.write(secrets + "\n")

    context = {"context": js_secrets_list}
    return context


def js_secrets(request):
    if request.method == "POST":
        form = JsSecrets()
        domain = str(request.POST.get("secret"))
        context = js_secrets_task.now(domain)
        return render(request, "testing/secret.html", context)
    else:
        return render(request, "testing/secret-index.html")


# LinkFinder
# Need to verify live js files
@background(schedule=1)
def js_links_task(domain):
    urls = requests.get(
        "http://web.archive.org/cdx/search/cdx?url=*.{}/*&output=json&fl=original&collapse=urlkey&limit=".format(
            domain
        )
    ).json()
    js_file_urls = []

    for link in urls:
        if re.search(r"\.js$", link[0]):
            js_file_urls.append(link[0])

    unique_js_file_urls = set(js_file_urls)

    try:
        os.chdir("testing/")
    except:
        print("Directory is already Testing")

    js_urls = []

    for js_link in unique_js_file_urls:
        result = subprocess.run(
            [sys.executable, "linkfinder.py", "-i", js_link, "-o", "cli"],
            stderr=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            text=True,
        )
        if result.stdout:
            if "Usage" in result.stdout:
                pass
            else:
                for item in result.stdout.splitlines():
                    js_urls.append(item)

    global linkfinder_output_file
    linkfinder_output_file = "{}_Linkfinder_{}.txt".format(domain, timestr)

    with open(linkfinder_output_file, "a+") as write_linkfinder_output:
        for line in js_urls:
            write_linkfinder_output.write(line + "\n")

    unique_js_links = set(js_urls)
    context = {"context": unique_js_links}
    return context


def js_links(request):
    if request.method == "POST":
        form = JsLinks()
        domain = str(request.POST.get("endpoint"))
        context = js_links_task.now(domain)
        return render(request, "testing/endpoint.html", context)
    else:
        form = JsLinks()
    return render(request, "testing/endpoint-index.html")


def full_scan(request):
    if request.method == "POST":
        domain = str(request.POST.get("fullscan"))

        try:
            os.chdir("testing/")
            print("Directory Changed")
        except:
            pass

        # Subdomain Discovery
        global subdomain_output_file
        subdomain_output_file = "{}_{}.txt".format(domain, timestr)
        subdom = sublist3r.main(
            domain,
            40,
            subdomain_output_file,
            ports=None,
            silent=True,
            verbose=False,
            enable_bruteforce=False,
            engines=None,
        )

        # Directory Brute-force
        directory_search = subprocess.run(
            [
                "python",
                "dirsearch/dirsearch.py",
                "-l",
                subdomain_output_file,
                "--full-url",
                "-q",
                "-t",
                "60",
                "-w",
                "dirsearch/robotsdis.txt",
            ],
            capture_output=True,
            text=True,
        )
        global directory_output_file
        directory_output_file = "Directory_{}.txt".format(timestr)

        with open(directory_output_file, "a+") as write_directory_output:
            write_directory_output.writelines(directory_search.stdout)

        directory_list = []

        with open(directory_output_file, "r") as r:
            for line in r:
                directory_list.append(line)

        status = []
        size = []
        directory_link = []

        for line in directory_list:
            item = line.split(" ")
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

        # Wayback
        wayback_urls = requests.get(
            "http://web.archive.org/cdx/search/cdx?url=*.{}/*&output=json&fl=original&collapse=urlkey&limit=".format(
                domain
            )
        ).json()
        wayback_urls_list = []

        for link in wayback_urls:
            wayback_urls_list.append(link[0])

        unique_wayback_urls = set(wayback_urls_list)
        global wayback_output_file
        wayback_output_file = "{}_Wayback_URLs_{}.txt".format(domain, timestr)

        with open(wayback_output_file, "a+") as write_wayback_output:
            for url in unique_wayback_urls:
                write_wayback_output.write(url + "\n")

        # JavaScript URLs
        js_file_urls = []

        for link in wayback_urls:
            if re.search(r"\.js$", link[0]):
                js_file_urls.append(link[0])

        unique_js_file_urls = set(js_file_urls)
        global jsurl_output_file
        jsurl_output_file = "{}_JS_URLs_{}.txt".format(domain, timestr)

        with open(jsurl_output_file, "a+") as write_jsurl_output:
            for url in unique_js_file_urls:
                write_jsurl_output.write(url + "\n")

        # JS Secrets
        js_secrets_list = []

        for url in unique_js_file_urls:
            js_secrets = subprocess.run(
                [sys.executable, "SecretFinder.py", "-i", url, "-o", "cli"],
                stderr=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                text=True,
            )
            if "->" in js_secrets.stdout:
                for item in js_secrets.stdout.splitlines():
                    js_secrets_list.append(item)

        global secret_output_file
        secret_output_file = "{}_JS_Secret_{}.txt".format(domain, timestr)

        with open(secret_output_file, "a+") as write_secret_output:
            for secrets in js_secrets_list:
                write_secret_output.write(secrets + "\n")

        # LinkFinder
        jsurls = []

        for js_link in unique_js_file_urls:
            result = subprocess.run(
                [sys.executable, "linkfinder.py", "-i", js_link, "-o", "cli"],
                stderr=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                text=True,
            )
            if result.stdout:
                if "Usage" in result.stdout:
                    pass
                else:
                    for item in result.stdout.splitlines():
                        jsurls.append(item)

        global linkfinder_output_file
        linkfinder_output_file = "{}_Linkfinder_{}.txt".format(domain, timestr)

        with open(linkfinder_output_file, "a+") as write_linkfinder_output:
            for line in jsurls:
                write_linkfinder_output.write(line + "\n")

        unique_js_links = set(jsurls)

        global fullscanContext
        fullscanContext = {
            "subdom": subdom,
            "directory_link": directory_link,
            "directory_size_status": directory_brute_link,
            "wayback_url": list(unique_wayback_urls),
            "js_url": list(unique_js_file_urls),
            "js_secrets": js_secrets_list,
            "js_link": list(unique_js_links),
        }
        return render(
            request, "testing/fullscan-overview.html", {"context": fullscanContext}
        )
    else:
        return render(request, "testing/fullscan-index.html")


def fullscan_result(request):
    if request.method == "GET":
        subdomain = request.GET.get("type", None)
        directory = request.GET.get("type", None)
        wayback = request.GET.get("type", None)
        jsurl = request.GET.get("type", None)
        secret = request.GET.get("type", None)
        link_finder = request.GET.get("type", None)

        if subdomain == "subdomain":
            sub_context = fullscanContext["subdom"]
            return render(
                request,
                "testing/fullscan-result.html",
                {"subdomain_context": sub_context},
            )

        if directory == "directory":
            dir_context = fullscanContext["directory_size_status"]
            return render(
                request,
                "testing/fullscan-result.html",
                {"directory_context": dir_context},
            )

        if wayback == "wayback":
            wayback_context = fullscanContext["wayback_url"]
            return render(
                request,
                "testing/fullscan-result.html",
                {"wayback_context": wayback_context},
            )

        if jsurl == "jsurl":
            jsurl_context = fullscanContext["js_url"]
            return render(
                request,
                "testing/fullscan-result.html",
                {"jsurl_context": jsurl_context},
            )

        if secret == "secrets":
            secret_context = fullscanContext["js_secrets"]
            return render(
                request,
                "testing/fullscan-result.html",
                {"secret_context": secret_context},
            )

        if link_finder == "linkfinder":
            linkfinder_context = fullscanContext["js_link"]
            return render(
                request,
                "testing/fullscan-result.html",
                {"linkfinder_context": linkfinder_context},
            )

        return render(request, "testing/fullscan-result.html")
    else:
        return render(request, "testing/fullscan.html")


def download_result(request):
    if request.method == "GET":
        subdomain = request.GET.get("scan", None)
        directory = request.GET.get("scan", None)
        wayback = request.GET.get("scan", None)
        jsurl = request.GET.get("scan", None)
        secret = request.GET.get("scan", None)
        link_finder = request.GET.get("scan", None)

        if subdomain == "subdomain":
            output_file = (
                f"/home/nihal/fwapf/testing/output/subdomain/{subdomain_output_file}"
            )
            filename = f"{subdomain_output_file}.txt"
            with open(output_file, "r") as fh:
                response = HttpResponse(fh.read(), content_type="text/html")
                response["Content-Disposition"] = "attachment; filename=%s" % filename
                return response

        if directory == "directory":
            output_file = (
                f"/home/nihal/fwapf/testing/output/directory/{directory_output_file}"
            )
            filename = f"{directory_output_file}.txt"
            with open(output_file, "r") as fh:
                response = HttpResponse(fh.read(), content_type="text/html")
                response["Content-Disposition"] = "attachment; filename=%s" % filename
                return response

        if wayback == "wayback":
            output_file = (
                f"/home/nihal/fwapf/testing/output/wayback/{wayback_output_file}"
            )
            filename = f"{wayback_output_file}.txt"
            with open(output_file, "r") as fh:
                response = HttpResponse(fh.read(), content_type="text/html")
                response["Content-Disposition"] = "attachment; filename=%s" % filename
                return response

        if jsurl == "jsurl":
            output_file = f"/home/nihal/fwapf/testing/output/jsurl/{jsurl_output_file}"
            filename = f"{jsurl_output_file}.txt"
            with open(output_file, "r") as fh:
                response = HttpResponse(fh.read(), content_type="text/html")
                response["Content-Disposition"] = "attachment; filename=%s" % filename
                return response

        if secret == "secret":
            output_file = (
                f"/home/nihal/fwapf/testing/output/secrets/{secret_output_file}"
            )
            filename = f"{secret_output_file}.txt"
            with open(output_file, "r") as fh:
                response = HttpResponse(fh.read(), content_type="text/html")
                response["Content-Disposition"] = "attachment; filename=%s" % filename
                return response

        if link_finder == "linkfinder":
            output_file = (
                f"/home/nihal/fwapf/testing/output/linkfinder/{linkfinder_output_file}"
            )
            filename = f"{linkfinder_output_file}.txt"
            with open(output_file, "r") as fh:
                response = HttpResponse(fh.read(), content_type="text/html")
                response["Content-Disposition"] = "attachment; filename=%s" % filename
                return response
    else:
        return render(request, "testing/index.html")