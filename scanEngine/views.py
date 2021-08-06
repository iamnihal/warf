from django.shortcuts import render
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import redirect
from django.contrib import messages
from django.urls import reverse
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.conf import settings
from tools.subbrute import subbrute
from tools import sublist3r
from background_task import background
from users.views import Scan
from .models import ResultFileName, Scan
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

domain_regex = re.compile(r"([a-z0-9]{2,}\.)+[a-z0-9]{2,5}")
url_regex = re.compile(
    r"https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()!@:%_\+.~#?&\/\/=]*)"
)
output_dir = os.path.join(settings.BASE_DIR, "output/")
tools_dir = os.path.join(settings.BASE_DIR, "tools/")

timestr = time.strftime("%Y-%m-%d-%H-%M")
subdomain_output_file = "Null"
directory_output_file = "Null"
wayback_output_file = "Null"
jsurl_output_file = "Null"
secret_output_file = "Null"
linkfinder_output_file = "Null"


def index(request):
    if not request.user.is_authenticated:
        messages.warning(
            request, 'To save your scans, you must first <a href="/login">log in</a>!!'
        )
        return render(request, "users/dashboard.html")
    else:
        return HttpResponseRedirect("dashboard/")


def about(request):
    return render(request, "scanEngine/about.html")


@login_required
def target_view(request, pk):
    if request.user.is_authenticated:
        target = Scan.objects.get(id=pk)
        scan_author = User.objects.get(scan=target)
        request_user = User.objects.get(id=request.user.id)
        if scan_author == request_user:
            scan_item = target
            scan_type = scan_item.scan_type
            scan_domain_url = scan_item.domain_url
            scan_date_posted = scan_item.scan_date
            scan_target_name = scan_item.target_name
            scan_is_bookmark = scan_item.is_bookmark
            result_filename = ResultFileName.objects.filter(scan_item=scan_item).first()
            if request.method == "POST":
                messages.success(request, "Scan Successfully Completed.")
                if scan_type == "Full Scan":
                    full_scan(request, scan_domain_url, pk)
                    return redirect("target-view", pk=scan_item.id)
                if scan_type == "Subdomain":
                    subdomain_finder(request, scan_domain_url, pk)
                    return redirect("target-view", pk=scan_item.id)
                elif scan_type == "Dirsearch":
                    directory_brute_force(request, scan_domain_url, pk)
                    return redirect("target-view", pk=scan_item.id)
                elif scan_type == "Wayback URL":
                    waybackurls(request, scan_domain_url, pk)
                    return redirect("target-view", pk=scan_item.id)
                elif scan_type == "JS File Discovery":
                    js_urls(request, scan_domain_url, pk)
                    return redirect("target-view", pk=scan_item.id)
                elif scan_type == "Secret/API key":
                    js_secrets(request, scan_domain_url, pk)
                    return redirect("target-view", pk=scan_item.id)
                elif scan_type == "Endpoint from JS":
                    js_links(request, scan_domain_url, pk)
                    return redirect("target-view", pk=scan_item.id)

            context = {
                "scan_type": scan_type,
                "scan_domain_url": scan_domain_url,
                "scan_date_posted": scan_date_posted,
                "scan_target_name": scan_target_name,
                "scan_item": scan_item,
                "result_filename": result_filename,
                "scan_is_bookmark": scan_is_bookmark,
            }

            if scan_type == "Full Scan":
                return render(request, "users/fullscan-detail.html", context)
            else:
                return render(request, "users/scan_detail.html", context)

        else:
            return render(request, "users/401.html")


@login_required
def scan_view(request, scantype):
    if request.method == "GET":
        user = request.user
        q = request.GET.get("q", None)
        if q:
            scans = Scan.objects.filter(
                author=user, target_name__icontains=q, scan_type=scantype
            )
            total_targets = scans.count()
            if total_targets == 0:
                messages.warning(request, "<center>Search not found!!</center>")
                return render(request, "users/overview.html")
        else:
            if scantype == "Secret":
                scans = Scan.objects.filter(scan_type="Secret/API key", author=user)
                total_targets = scans.count()
            else:
                scans = Scan.objects.filter(scan_type=scantype, author=user).order_by(
                    "-scan_date"
                )
                total_targets = scans.count()

        if not scans:
            messages.warning(
                request, 'You dont have any targets. <a href="/add-target/">Add one</a>'
            )
            return render(request, "users/targets.html")

        paginator = Paginator(scans, 8)
        page_number = request.GET.get("page")
        page_obj = paginator.get_page(page_number)

    return render(
        request,
        "users/overview.html",
        {
            "context": page_obj,
            "total_targets": total_targets,
            "scan_type": scantype,
            "page_number": page_number,
        },
    )


@login_required
def dash_scan(request):
    if request.method == "GET":
        user = request.user
        q = request.GET.get("q", None)
        targets = Scan.objects.filter(author=User.objects.get(username=user)).order_by(
            "-scan_date"
        )
        scans = ResultFileName.objects.filter(scan_item__in=targets).order_by(
            "-scan_item__scan_date"
        )
        total_targets = scans.count()

        if q:
            tempScan = (
                Scan.objects.filter(resultfilename__in=scans)
                .filter(target_name__icontains=q)
                .order_by("-scan_date")
            )
            return render(request, "users/dash-scan.html", {"scans": tempScan, "q": q})

        paginator = Paginator(scans, 8)
        page_number = request.GET.get("page")
        page_obj = paginator.get_page(page_number)

        return render(
            request,
            "users/dash-scan.html",
            {"scans": page_obj, "total_targets": total_targets},
        )


def target_delete(request, pk):
    request_user = request.user
    target = Scan.objects.get(id=pk)
    target_owner = User.objects.get(scan=target)
    if request_user == target_owner:
        if request.method == "POST":
            if request_user == target_owner:
                target.delete()
                messages.success(request, f'"{target.target_name}" target deleted')
                return redirect("/targets")
            else:
                return render(request, "users/401.html")
    else:
        return render(request, "users/401.html")
    context = {"target": target}
    return render(request, "users/target-delete.html", context)


def scan_search(request):
    if request.method == "GET":
        q = request.GET.get("q")
        user = request.user
        if q:
            targets = Scan.objects.filter(
                author=User.objects.filter(username=user).first()
            )
            scanFiles = ResultFileName.objects.filter(scan_item__in=targets)
            scans = Scan.objects.filter(resultfilename__in=scanFiles).filter(
                target_name__icontains=q
            )
            return render(
                request, "users/scan-search-result.html", {"context": scans, "q": q}
            )
        else:
            messages.warning(request, "<center>Search not found!!</center>")
            return render(request, "users/scan-search-result.html")

    else:
        return render(request, "users/dash-scan.html")


@login_required
def scan_result(request, pk):
    result_filename = ResultFileName.objects.filter(
        scan_item=Scan.objects.get(id=pk)
    ).first()
    scan_type = request.GET.get("scan", None)
    user = request.user
    try:
        target_owner = result_filename.scan_item.author
    except:
        return render(request, "users/404.html")

    output_dir = os.path.join(settings.BASE_DIR, "output/")
    if user == target_owner:
        context = None
        if scan_type == "Subdomain":
            for file in os.listdir(output_dir + 'subdomain'):
                if re.match(file, str(result_filename)):
                    with open(output_dir + f"subdomain/{file}", "r") as rf:
                        context = rf.readlines()

            if context is None:
                messages.warning(request, "Scan is in process. Please wait.")
                return render(request, "scanEngine/subdomain.html", {"subdom": context})

            return render(request, "scanEngine/subdomain.html", {"subdom": context})

        if scan_type == "Dirsearch":
            data = None
            for file in os.listdir(output_dir + 'directory'):
                if re.match(file, str(result_filename)):
                    with open(output_dir + f"/directory/{file}", "r") as rf:
                        data = rf.readlines()[2:]

            if data is None:
                messages.warning(request, "Scan is in process. Please wait.")
                return render(
                    request, "scanEngine/subdomain.html", {"context": context}
                )

            status = []
            size = []
            directory_link = []

            for line in data:
                row = re.split(" +", line)
                status.append(row[0])
                size.append(row[1])
                directory_link.append(row[2])

            context = zip(directory_link, size, status)

            if context is None:
                messages.warning(request, "Scan is in process. Please wait.")
                return render(
                    request, "scanEngine/subdomain.html", {"context": context}
                )

            return render(request, "scanEngine/directory.html", {"context": context})

        if scan_type == "Wayback URL":
            data = ""
            for file in os.listdir(output_dir + 'wayback'):
                if re.match(file, str(result_filename)):
                    with open(output_dir + f"/wayback/{file}", "r") as rf:
                        data = rf.readlines()

            if data:
                return render(request, "scanEngine/wayback.html", {"context": data})
            else:
                messages.warning(request, "Scan is in process. Please wait.")
                return render(request, "scanEngine/wayback.html", {"context": data})

        if scan_type == "JS File Discovery":
            for file in os.listdir(output_dir + 'jsurl'):
                if re.match(file, str(result_filename)):
                    with open(output_dir + f"/jsurl/{file}", "r") as rf:
                        data = rf.readlines()

            return render(request, "scanEngine/jsurl.html", {"context": data})

        if scan_type == "Secret/API key":
            for file in os.listdir(output_dir + 'secrets'):
                if re.match(file, str(result_filename)):
                    with open(output_dir + f"secrets/{file}", "r") as rf:
                        data = rf.readlines()

            return render(request, "scanEngine/secret.html", {"context": data})

        if scan_type == "Endpoint from JS":
            for file in os.listdir(output_dir + 'linkfinder'):
                if re.match(file, str(result_filename)):
                    with open(output_dir + f"/linkfinder/{file}", "r") as rf:
                        data = rf.readlines()

            return render(request, "scanEngine/endpoint.html", {"context": data})

    return render(request, "users/401.html")


def handle_uploaded_file(f):
    global wordlist_name
    wordlist_name = f'{os.path.splitext(f.name)[0]}-{time.strftime("%M-%S")}.txt'
    with open(os.path.join(settings.BASE_DIR, f'scanEngine/wordlist/{wordlist_name}'), "ab+") as destination:
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
    return render(request, "scanEngine/wordlist.html")


# AJAX Call
def ajax_call(request):
    scan = request.GET.get("scan", None)
    if scan == "subdomain":
        output_file = output_dir + f'subdomain/{subdomain_output_file}'
    if scan == "directory":
        output_file = output_dir + f'directory/{directory_output_file}'
    if scan == "wayback":
        output_file = output_dir + f'wayback/{wayback_output_file}'
    if scan == "jsurl":
        output_file = output_dir + f'jsurl/{jsurl_output_file}'
    if scan == "secret":
        output_file = output_dir + f'secrets/{secret_output_file}'
    if scan == "linkfinder":
        output_file = output_dir + f'linkfinder/{linkfinder_output_file}'

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
    except FileNotFoundError:
        return HttpResponse("FileDoesNotExist")
    except NameError:
        return HttpResponse("FileNotFound")
    except ValueError:
        return HttpResponse("ValueError")


# Subdomain Finder
@background(schedule=1)
def subdomain_finder_task(subdomain, gitSubdomain, gitToken, pk=None):

    if subdomain != "None":
        global subdomain_output_file
        subdomain_output_file = "{}_{}.txt".format(subdomain, timestr)

        if pk is not None:
            scan_target = Scan.objects.get(id=pk)
            ResultFileName.objects.create(
                file_name=subdomain_output_file, scan_item=scan_target
            )

        subdom = sublist3r.main(
            subdomain,
            40,
            subdomain_output_file,
            ports=None,
            silent=True,
            verbose=True,
            enable_bruteforce=False,
            engines=None,
        )

        subprocess.run(
            [
                "mv",
                os.path.join(settings.BASE_DIR, f"{subdomain_output_file}"),
                os.path.join(settings.BASE_DIR, f"output/subdomain/"),
            ]
        )

        context = {"subdom": subdom}
        return context

    if gitSubdomain != "None":
        gitsubs = "github_subs_{}.txt".format(timestr)
        result = subprocess.run(
            [
                "python",
                tools_dir + 'github-subdomains.py',
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


def subdomain_finder(request, domain_url=None, pk=None):
    if request.method == "POST":
        subdomain = str(request.POST.get("subdomain", domain_url))
        gitSubdomain = str(request.POST.get("github-subdomain", None))
        gitToken = str(request.POST.get("github-token", None))
        global sub_context
        if re.match(domain_regex, subdomain) or re.match(domain_regex, gitSubdomain):
            sub_context = subdomain_finder_task.now(
                subdomain, gitSubdomain, gitToken, pk
            )
            return render(request, "scanEngine/subdomain.html", sub_context)
        else:
            messages.warning(request, "Invalid Domain")
            return render(request, "scanEngine/subdomain-index.html")
    else:
        return render(request, "scanEngine/subdomain-index.html")


# Directory Brute Force
@background(schedule=1)
def directory_brute_force_task(directory, pk=None):
    global directory_output_file
    directory_output_file = "Directory_{}.txt".format(timestr)

    if pk is not None:
        scan_target = Scan.objects.get(id=pk)
        ResultFileName.objects.create(
            file_name=directory_output_file, scan_item=scan_target
        )

    if dir_wordlist == "on":
        os.chdir("./wordlist")
        files = sorted(os.listdir(os.getcwd()), key=os.path.getmtime)
        wordlist_file = files[-1]
        os.chdir("../")
        directory_search = subprocess.run(
            [
                "python",
                tools_dir + 'dirsearch/dirsearch.py',
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
                sys.executable,
                tools_dir + "dirsearch/dirsearch.py",
                "-u",
                directory,
                "-t",
                "60",
                "-w",
                tools_dir + 'dirsearch/robotsdis.txt',
                "--plain-text-report",
                directory_output_file,
            ],
            capture_output=True,
            text=True,
        )

    subprocess.run(
        [
            "mv",
            os.path.join(settings.BASE_DIR, f"{directory_output_file}"),
            os.path.join(settings.BASE_DIR, f"output/directory/"),
        ]
    )

    with open(
        output_dir + f"directory/{directory_output_file}", "r"
    ) as read_directory_file:
        data = read_directory_file.readlines()[2:]

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


def directory_brute_force(request, domain_url=None, pk=None):
    if request.method == "POST":
        directory = str(request.POST.get("directory", domain_url))
        global dir_wordlist
        dir_wordlist = request.POST.get("wordlist")
        global dir_context
        if re.match(url_regex, directory):
            dir_context = directory_brute_force_task.now(directory, pk)
            return render(
                request, "scanEngine/directory.html", {"context": dir_context}
            )
        else:
            messages.warning(request, "Invalid Directory")
            return render(request, "scanEngine/directory-index.html")
    else:
        return render(request, "scanEngine/directory-index.html")


# Wayback URLs
@background(schedule=1)
def waybackurls_task(domain, pk=None):

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

    if pk is not None:
        scan_target = Scan.objects.get(id=pk)
        ResultFileName.objects.create(
            file_name=wayback_output_file, scan_item=scan_target
        )

    with open(
        output_dir + f"wayback/{wayback_output_file}", "a+"
    ) as write_wayback_urls:
        for url in unique_wayback_urls:
            write_wayback_urls.write(url + "\n")

    context = {"context": unique_wayback_urls}
    return context


def waybackurls(request, domain_url=None, pk=None):
    if request.method == "POST":
        form = Waybackurls()
        domain = str(request.POST.get("wayback", domain_url))
        if re.match(domain_regex, domain):
            context = waybackurls_task.now(domain, pk)
            return render(request, "scanEngine/wayback.html", context)
        else:
            messages.warning(request, "Invalid Domain")
            return render(request, "scanEngine/wayback-index.html")
    else:
        form = Waybackurls()
    return render(request, "scanEngine/wayback-index.html")


# JavaScript URLs
@background(schedule=1)
def js_urls_task(domain, pk=None):
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
        os.chdir("scanEngine/")
    except:
        pass

    global jsurl_output_file
    jsurl_output_file = "{}_JS_URLs_{}.txt".format(domain, timestr)

    if pk is not None:
        scan_target = Scan.objects.get(id=pk)
        ResultFileName.objects.create(
            file_name=jsurl_output_file, scan_item=scan_target
        )

    with open(output_dir + f"jsurl/{jsurl_output_file}", "a+") as write_js_file:
        for url in unique_js_file_urls:
            write_js_file.write(url + "\n")

    context = {"context": unique_js_file_urls}
    return context


def js_urls(request, domain_url=None, pk=None):
    if request.method == "POST":
        form = JsFiles()
        domain = str(request.POST.get("jsurl", domain_url))
        if re.match(domain_regex, domain):
            context = js_urls_task.now(domain, pk)
            return render(request, "scanEngine/jsurl.html", context)
        else:
            messages.warning(request, "Invalid Domain")
            return render(request, "scanEngine/jsurl-index.html")
    else:
        form = JsFiles()
    return render(request, "scanEngine/jsurl-index.html")


# JS Secrets
@background(schedule=1)
def js_secrets_task(domain, pk=None):

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
            [sys.executable, tools_dir + 'SecretFinder.py', "-i", url, "-o", "cli"],
            stderr=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            text=True,
        )
        if "->" in js_secrets.stdout:
            for item in js_secrets.stdout.splitlines():
                js_secrets_list.append(item)

    global secret_output_file
    secret_output_file = "{}_JS_Secret_{}.txt".format(domain, timestr)

    if pk is not None:
        scan_target = Scan.objects.get(id=pk)
        ResultFileName.objects.create(
            file_name=secret_output_file, scan_item=scan_target
        )

    with open(output_dir + f"secrets/{secret_output_file}", "a+") as secret_file:
        for secrets in js_secrets_list:
            secret_file.write(secrets + "\n")

    context = {"context": js_secrets_list}
    return context


def js_secrets(request, domain_url=None, pk=None):
    if request.method == "POST":
        form = JsSecrets()
        domain = str(request.POST.get("secret", domain_url))
        if re.match(domain_regex, domain):
            context = js_secrets_task.now(domain, pk)
            return render(request, "scanEngine/secret.html", context)
        else:
            messages.warning(request, "Invalid Domain")
            return render(request, "scanEngine/secret-index.html")
    else:
        return render(request, "scanEngine/secret-index.html")


# LinkFinder
@background(schedule=1)
def js_links_task(domain, pk=None):
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

    js_urls = []

    for js_link in unique_js_file_urls:
        result = subprocess.run(
            [sys.executable, tools_dir + 'linkfinder.py', "-i", js_link, "-o", "cli"],
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

    if pk is not None:
        scan_target = Scan.objects.get(id=pk)
        ResultFileName.objects.create(
            file_name=linkfinder_output_file, scan_item=scan_target
        )

    unique_js_links = set(js_urls)

    with open(
        output_dir + f"linkfinder/{linkfinder_output_file}", "a+"
    ) as write_linkfinder_output:
        for line in unique_js_links:
            write_linkfinder_output.write(line + "\n")

    context = {"context": unique_js_links}
    return context


def js_links(request, domain_url=None, pk=None):
    if request.method == "POST":
        form = JsLinks()
        domain = str(request.POST.get("endpoint", domain_url))
        if re.match(domain_regex, domain):
            context = js_links_task.now(domain, pk)
            return render(request, "scanEngine/endpoint.html", context)
        else:
            messages.warning(request, "Invalid Domain")
            return render(request, "scanEngine/endpoint-index.html")
    else:
        form = JsLinks()
    return render(request, "scanEngine/endpoint-index.html", {"context": form})


@background(schedule=1)
def full_scan_task(domain, pk=None):

    # Subdomain Discovery
    global subdomain_output_file
    subdomain_output_file = "{}_{}.txt".format(domain, timestr)
    subdom = sublist3r.main(
        domain,
        40,
        subdomain_output_file,
        ports=None,
        silent=False,
        verbose=True,
        enable_bruteforce=False,
        engines=None,
    )

    subprocess.run(
        [
            "mv",
            os.path.join(settings.BASE_DIR, f"{subdomain_output_file}"),
            os.path.join(settings.BASE_DIR, f"output/subdomain/"),
        ]
    )

    # Directory Brute-force
    directory_search = subprocess.run(
        [
            "python",
            tools_dir + 'dirsearch/dirsearch.py',
            "-l",
            os.path.join(
                settings.BASE_DIR, f"output/subdomain/{subdomain_output_file}"
            ),
            "--full-url",
            "-q",
            "-t",
            "60",
            "-w",
            tools_dir + 'dirsearch/robotsdis.txt',
        ],
        capture_output=True,
        text=True,
    )
    global directory_output_file
    directory_output_file = "Directory_{}.txt".format(timestr)

    with open(
        output_dir + f"directory/{directory_output_file}", "a+"
    ) as write_directory_output:
        write_directory_output.writelines(directory_search.stdout)

    directory_list = []

    with open(output_dir + f"directory/{directory_output_file}", "r") as r:
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

    with open(
        output_dir + f"wayback/{wayback_output_file}", "a+"
    ) as write_wayback_output:
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

    with open(output_dir + f"jsurl/{jsurl_output_file}", "a+") as write_jsurl_output:
        for url in unique_js_file_urls:
            write_jsurl_output.write(url + "\n")

    # JS Secrets
    js_secrets_list = []

    for url in unique_js_file_urls:
        js_secrets = subprocess.run(
            [sys.executable, tools_dir + 'SecretFinder.py', "-i", url, "-o", "cli"],
            stderr=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            text=True,
        )
        if "->" in js_secrets.stdout:
            for item in js_secrets.stdout.splitlines():
                js_secrets_list.append(item)

    global secret_output_file
    secret_output_file = "{}_JS_Secret_{}.txt".format(domain, timestr)

    unique_js_secrets_list = set(js_secrets_list)
    with open(
        output_dir + f"secrets/{secret_output_file}", "a+"
    ) as write_secret_output:
        for secrets in unique_js_secrets_list:
            write_secret_output.write(secrets + "\n")

    # LinkFinder
    jsurls = []

    for js_link in unique_js_file_urls:
        result = subprocess.run(
            [sys.executable, tools_dir + 'linkfinder.py', "-i", js_link, "-o", "cli"],
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

    unique_js_links = set(jsurls)

    with open(
        output_dir + f"linkfinder/{linkfinder_output_file}",
        "a+",
    ) as write_linkfinder_output:
        for line in unique_js_links:
            write_linkfinder_output.write(line + "\n")

    global fullscanContext
    fullscanContext = {
        "subdom": subdom,
        "directory_link": directory_link,
        "directory_size_status": directory_brute_link,
        "wayback_url": list(unique_wayback_urls),
        "js_url": list(unique_js_file_urls),
        "js_secrets": js_secrets_list,
        "js_link": unique_js_links,
    }

    if pk is not None:
        scan_target = Scan.objects.get(id=pk)
        scan_filenames = [
            subdomain_output_file,
            directory_output_file,
            wayback_output_file,
            jsurl_output_file,
            secret_output_file,
            linkfinder_output_file,
        ]
        filename_objs = [
            ResultFileName(file_name=name, scan_item=scan_target)
            for name in scan_filenames
        ]
        ResultFileName.objects.bulk_create(filename_objs)

    return fullscanContext


def full_scan(request, domain_url=None, pk=None):
    if request.method == "POST":
        domain = str(request.POST.get("fullscan", domain_url))
        if re.match(domain_regex, domain):
            context = full_scan_task.now(domain, pk)
            return render(
                request, "scanEngine/fullscan-overview.html", {"context": context}
            )
        else:
            messages.warning(request, "Invalid Domain")
            return render(request, "scanEngine/fullscan-index.html")
    else:
        return render(request, "scanEngine/fullscan-index.html")


def fullscan_overview(request, pk):
    target = Scan.objects.get(id=pk)
    result_filenames = ResultFileName.objects.filter(scan_item=target)
    subdomain_file = result_filenames[0]
    directory_file = result_filenames[1]
    wayback_file = result_filenames[2]
    jsurl_file = result_filenames[3]
    secret_file = result_filenames[4]
    linkfinder_file = result_filenames[5]

    with open(output_dir + f"subdomain/{subdomain_file}", "r") as read_subdomain_file:
        subdom = read_subdomain_file.readlines()

    with open(output_dir + f"directory/{directory_file}", "r") as read_directory_file:
        data = read_directory_file.readlines()[2:]

    status = []
    size = []
    directory_link = []

    for line in data:
        row = re.split(" +", line)
        try:
            status.append(row[0])
            size.append(row[2])
            directory_link.append(row[4])
        except IndexError:
            pass

    directory_brute_link = zip(directory_link, size, status)

    with open(output_dir + f"wayback/{wayback_file}", "r") as read_wayback_file:
        unique_wayback_urls = read_wayback_file.readlines()

    with open(output_dir + f"jsurl/{jsurl_file}", "r") as read_jsurl_file:
        unique_js_file_urls = read_jsurl_file.readlines()

    with open(output_dir + f"secrets/{secret_file}", "r") as read_secret_file:
        js_secrets_list = read_secret_file.readlines()

    with open(
        output_dir + f"linkfinder/{linkfinder_file}", "r"
    ) as read_linkfinder_file:
        unique_js_links = read_linkfinder_file.readlines()

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
        request, "scanEngine/fullscan-overview.html", {"context": fullscanContext}
    )


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
                "scanEngine/fullscan-result.html",
                {"subdomain_context": sub_context},
            )

        if directory == "directory":
            dir_context = fullscanContext["directory_size_status"]
            return render(
                request,
                "scanEngine/fullscan-result.html",
                {"directory_context": dir_context},
            )

        if wayback == "wayback":
            wayback_context = fullscanContext["wayback_url"]
            return render(
                request,
                "scanEngine/fullscan-result.html",
                {"wayback_context": wayback_context},
            )

        if jsurl == "jsurl":
            jsurl_context = fullscanContext["js_url"]
            return render(
                request,
                "scanEngine/fullscan-result.html",
                {"jsurl_context": jsurl_context},
            )

        if secret == "secrets":
            secret_context = fullscanContext["js_secrets"]
            return render(
                request,
                "scanEngine/fullscan-result.html",
                {"secret_context": secret_context},
            )

        if link_finder == "linkfinder":
            linkfinder_context = fullscanContext["js_link"]
            return render(
                request,
                "scanEngine/fullscan-result.html",
                {"linkfinder_context": linkfinder_context},
            )

        return render(request, "scanEngine/fullscan-result.html")
    else:
        return render(request, "scanEngine/fullscan.html")


@login_required
def download_target_result(request, pk):
    if request.method == "GET":
        user = request.user
        target = Scan.objects.get(id=pk)
        target_owner = User.objects.get(scan=target)
        fullscan = request.GET.get("scan", None)
        subdomain = request.GET.get("scan", None)
        directory = request.GET.get("scan", None)
        wayback = request.GET.get("scan", None)
        jsurl = request.GET.get("scan", None)
        secret = request.GET.get("scan", None)
        link_finder = request.GET.get("scan", None)

        if user == target_owner:
            if subdomain == "subdomain":
                subdomain_output_file = ResultFileName.objects.get(scan_item=target)
                if subdomain_output_file == "Null" or subdomain_output_file is None:
                    pass

                output_file = output_dir + f"subdomain/{subdomain_output_file}"
                filename = f"{subdomain_output_file}"
                with open(output_file, "r") as fh:
                    response = HttpResponse(fh.read(), content_type="text/html")
                    response["Content-Disposition"] = (
                        "attachment; filename=%s" % filename
                    )
                    return response

            if directory == "directory":
                directory_output_file = ResultFileName.objects.get(scan_item=target)

                output_file = output_dir + f"directory/{directory_output_file}"
                filename = f"{directory_output_file}"
                with open(output_file, "r") as fh:
                    response = HttpResponse(fh.read(), content_type="text/html")
                    response["Content-Disposition"] = (
                        "attachment; filename=%s" % filename
                    )
                    return response

            if wayback == "wayback":
                output_file = output_dir + f"wayback/{wayback_output_file}"
                filename = f"{wayback_output_file}"
                with open(output_file, "r") as fh:
                    response = HttpResponse(fh.read(), content_type="text/html")
                    response["Content-Disposition"] = (
                        "attachment; filename=%s" % filename
                    )
                    return response

            if jsurl == "jsurl":
                output_file = output_dir + f"jsurl/{jsurl_output_file}"
                filename = f"{jsurl_output_file}"
                with open(output_file, "r") as fh:
                    response = HttpResponse(fh.read(), content_type="text/html")
                    response["Content-Disposition"] = (
                        "attachment; filename=%s" % filename
                    )
                    return response

            if secret == "secret":
                if pk is not None:
                    secret_output_file = ResultFileName.objects.get(scan_item=target)

                output_file = output_dir + f"secret/{secret_output_file}"
                filename = f"{secret_output_file}"
                with open(output_file, "r") as fh:
                    response = HttpResponse(fh.read(), content_type="text/html")
                    response["Content-Disposition"] = (
                        "attachment; filename=%s" % filename
                    )
                    return response

            if link_finder == "linkfinder":
                output_file = output_dir + f"linkfinder/{linkfinder_output_file}"
                filename = f"{linkfinder_output_file}"
                with open(output_file, "r") as fh:
                    response = HttpResponse(fh.read(), content_type="text/html")
                    response["Content-Disposition"] = (
                        "attachment; filename=%s" % filename
                    )
                    return response

        else:
            return HttpResponse("Lol. It won't work. :p")
    else:
        return render(request, "scanEngine/index.html")


def download_result(request, pk=None):
    if request.method == "GET":
        subdomain = request.GET.get("scan", None)
        directory = request.GET.get("scan", None)
        wayback = request.GET.get("scan", None)
        jsurl = request.GET.get("scan", None)
        secret = request.GET.get("scan", None)
        link_finder = request.GET.get("scan", None)

        output_dir = os.path.join(settings.BASE_DIR, "output/")

        if subdomain == "subdomain":
            output_file = output_dir + f"subdomain/{subdomain_output_file}"
            filename = f"{subdomain_output_file}"
            with open(output_file, "r") as fh:
                response = HttpResponse(
                    fh.read(), content_type="text/plain charset=utf-8"
                )
                response["Content-Disposition"] = "attachment; filename=%s" % filename
                return response

        if directory == "directory":
            output_file = output_dir + f"directory/{directory_output_file}"
            filename = f"{directory_output_file}"
            with open(output_file, "r") as fh:
                response = HttpResponse(fh.read(), content_type="text/html")
                response["Content-Disposition"] = "attachment; filename=%s" % filename
                return response

        if wayback == "wayback":
            output_file = output_dir + f"wayback/{wayback_output_file}"
            filename = f"{wayback_output_file}"
            with open(output_file, "r") as fh:
                response = HttpResponse(fh.read(), content_type="text/html")
                response["Content-Disposition"] = "attachment; filename=%s" % filename
                return response

        if jsurl == "jsurl":
            output_file = output_dir + f"jsurl/{jsurl_output_file}"
            filename = f"{jsurl_output_file}"
            with open(output_file, "r") as fh:
                response = HttpResponse(fh.read(), content_type="text/html")
                response["Content-Disposition"] = "attachment; filename=%s" % filename
                return response

        if secret == "secret":
            if pk is not None:
                secret_output_file = ResultFileName.objects.filter(
                    scan_item=Scan.objects.get(id=pk)
                ).first()

            output_file = output_dir + f"secret/{secret_output_file}"
            filename = f"{secret_output_file}"
            with open(output_file, "r") as fh:
                response = HttpResponse(fh.read(), content_type="text/html")
                response["Content-Disposition"] = "attachment; filename=%s" % filename
                return response

        if link_finder == "linkfinder":
            output_file = output_dir + f"linkfinder/{linkfinder_output_file}"
            filename = f"{linkfinder_output_file}"
            with open(output_file, "r") as fh:
                response = HttpResponse(fh.read(), content_type="text/html")
                response["Content-Disposition"] = "attachment; filename=%s" % filename
                return response
    else:
        return render(request, "users/dashboard.html")