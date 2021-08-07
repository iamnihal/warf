# base image
FROM python:3.8

# setup environment variable
ENV PYTHONUNBUFFERED 1

# set work directory
RUN mkdir /wapf

# where code lives
WORKDIR /wapf

# copy the current directory contents into the container at /wapf
ADD . /wapf/

# install needed packages
RUN pip install -r requirements.txt

# port where django app runs
EXPOSE 8000

# start server
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]