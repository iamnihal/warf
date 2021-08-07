<h1 align="center">WARF: Web Application Reconnaissance Framework</h1>

[![version](https://img.shields.io/badge/version-0.1-red)](https://www.github.com/iamnihal/warf)
[![python](https://img.shields.io/badge/python-3.8.1-blue.svg?logo=python&labelColor=yellow)](https://www.python.org/downloads/)
[![django](https://img.shields.io/badge/django-3.1.7-blue.svg?logo=django&labelColor=grey)](https://www.python.org/downloads/)
[![platform](https://img.shields.io/badge/platform-osx%2Flinux%2Fwindows-green.svg)](https://github.com/iamnihal/warf/)
  <br />

![Dashboard](https://user-images.githubusercontent.com/37813784/128590378-c8e84910-7bf9-4356-9b0b-6aa8931bb276.JPG)

## Table of Contents

* [About WARF](#about-warf)
    * [What is WARF](#about-warf)
* [Main Features](#main-features)
* [Screenshots](#screenshots)
* [Installation](#installation)
* [Contributing](#contributing)
* [License](#license)
* [Acknowledgements & Credits](#acknowledgements-and-credits)

## About WARF
<p>WARF is a Recon framework for web application. It comprises different tools to perform information gathering on the target such as subdomain enumeration, directory bruteforce, gathering all sorts of endpoints like wayback URLs, JS URLs, endpoints from JS files, API/Secret keys etc.</p>
<p>WARF is highly customizable and allows you to perform full scan or individual scan on the target. It accumulate the results and show it in a powerful DataTable throug   h which you can narrow down your searches. WARF also give you the option to add and save target individually, and perform different scans on them. </p>
<p>With a Dashboard, you will quickly gets the metrics of your activity. WARF confined all your targets together and gives you a clean and efficient way to search them down with their name.</p>

### Main Features
- Subdomain Enumeration
- Directory BruteForce
- Gather Wayback URLs
- Gather JavaScript URLs
- Extract links from JS files
- Extract API/Secret Keys from JS files
- Supports Background Scan

### Screenshots

#### FullScan
![fullscan](https://user-images.githubusercontent.com/37813784/128592964-ecb70439-d2a4-42bb-a952-e9b23ac95b50.JPG)

#### Subdomain Enumeration
![subdomain](https://user-images.githubusercontent.com/37813784/128593177-59cf5d7a-a68b-4d99-82fa-1275407e01f0.JPG)

#### Add Target
![target](https://user-images.githubusercontent.com/37813784/128593013-b5097bb1-af36-45d1-93d9-77a8a1a1c23a.JPG)

#### View Target
![target2](https://user-images.githubusercontent.com/37813784/128593023-06cf3709-4008-4b88-b450-d8afad810444.JPG)

#### View Details
![targetview](https://user-images.githubusercontent.com/37813784/128593119-2c93d433-914a-4bb0-ab35-dfb10da5dff9.JPG)

#### View Result
![result](https://user-images.githubusercontent.com/37813784/128593030-6c431f13-8d6f-4ecb-8f4d-17fef24b9039.JPG)

### Installation
You can install WARF in two ways:-
 - #### By creating a python virtual environment and git cloning the repository.

1) Create a virtualenv:
```
$ python3 -m venv <virtual env path>
```
2) Activate the virtualenv you have just created:
```
$ source <virtual env path>/bin/activate
```
3) Clone this repository:
```
$ git clone https://github.com/iamnihal/warf.git
````
4) Install the requirements:
```
$ pip install -r requirements.txt
```
5) Apply migrations:
```
$ python manage.py migrate
```
6) Run the server:
```
$ python manage.py runserver
```

and load the app at http://127.0.0.1:8000

- #### Using Docker

If you don't have Docker installed on your system, you can follow up with the [official Docker installation guide.](https://docs.docker.com/get-docker/)
1) Start by cloning the repository:
```
$ git clone https://github.com/iamnihal/warf.git
```
2) Build the Docker image:
```
$ docker build -t warf .
```
3) Build and run Docker container:
```
$ docker run --name warf -d -p 8000:8000 warf
```
and now your app is ready to launch at http://127.0.0.1:8000
 
<!-- CONTRIBUTING -->
## Contributing

If you want to contribute to this project and make it better, your help is very welcome. As this is my first ever project in Django, there could exist a lot of caveats and other coding related issues. Your contribution to this project helps me to learn and inspire to build more awesome projects in future. Contributing is also a great way to learn more about social coding on Github, new technologies and and their ecosystems. Contributions are what make the open source community such an amazing place to be learn, inspire, and create. Any contributions you make are **greatly appreciated**.

<!-- LICENSE -->
## License

Distributed under the MIT License. See [LICENSE](LICENSE) for more information.

<!-- CONTACT -->
## Contact

Nihal - [@iamnihal_](https://twitter.com/iamnihal_) - infosec.nihal@gmail.com

Project Link: [https://github.com/iamnihal/warf](https://github.com/iamnihal/warf)



<!-- ACKNOWLEDGEMENTS -->
## Acknowledgements and Credits
All the tools in WARF have been created by these awesome people:
1) [Sublist3r](https://github.com/aboul3la/Sublist3r):- aboul3la 
2) [github-subdomain.py](https://github.com/gwen001/github-search/blob/master/github-subdomains.py):- gwen001
3) [Dirsearch](https://github.com/maurosoria/dirsearch):- maurosoria 
4) [SecretFinder](https://github.com/m4ll0k/SecretFinder):- m4ll0k 
5) [Linkfinder](https://github.com/GerbenJavado/LinkFinder):- GerbenJavado 

