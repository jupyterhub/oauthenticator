# Designed to be run as 
# 
# docker run -it -p 8000:8000 jupyter/oauthenticator

FROM jupyter/jupyterhub

MAINTAINER Project Jupyter <ipython-dev@scipy.org>

# Install oauthenticator from git
RUN pip3 install git+git://github.com/jupyter/oauthenticator.git

# Create oauthenticator directory and put necessary files in it
RUN mkdir /srv/oauthenticator
WORKDIR /srv/oauthenticator
ENV OAUTHENTICATOR_DIR /srv/oauthenticator
ADD addusers.sh /srv/oauthenticator/addusers.sh
ADD userlist /srv/oauthenticator/userlist
ADD ssl /srv/oauthenticator/ssl
RUN chmod 700 /srv/oauthenticator

RUN ["sh", "/srv/oauthenticator/addusers.sh"]
