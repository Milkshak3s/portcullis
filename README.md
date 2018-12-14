# PORTCULLIS
[![CircleCI](https://circleci.com/gh/ritsec-dev/portcullis.svg?style=svg)](https://circleci.com/gh/ritsec-dev/portcullis)
![LGTM Grade](https://img.shields.io/lgtm/grade/python/g/ritsec-dev/portcullis.svg)  
A simple token-based auth system


## Local Testing
Build the docker image with:  
```docker build -t "portcullis:latest" .```

Run the docker image with:  
v0/auth-decorators
```docker run -p 443:443 portcullis```


## Decorator Usage
Import and setup the class containing the decorator:  
```
from pcauth import PortcullisAuth

pc = PortcullisAuth("localhost", 80)
```  

To automatically auth the current path:  
```
@pc.recauth()
def someroute():
```  

To auth a different resource path:  
```
@pc.recauth("/path/to/resource")
def someroute():
```  

To auth a speicific named permission:  
```
@pc.permauth("permission_name"):
def someroute():
```  
