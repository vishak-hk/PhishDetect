from urllib.parse import urlparse, urlencode
import ipaddress
import re
from bs4 import BeautifulSoup
import whois
import urllib
import urllib.request
from datetime import datetime
import requests


class DETECTION:
    shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                          r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                          r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                          r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                          r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                          r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                          r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                          r"tr\.im|link\.zip\.net"

    def getDomain(self,url):  # 1.Domain of the URL (Domain)
        domain = urlparse(url).netloc
        if re.match(r"^www.", domain):
            domain = domain.replace("www.", "")
            return domain

    def havingIP(self,url):
        try:
            ipaddress.ip_address(url)
            ip = 1
        except:
            ip = 0
        return ip

    def haveAtSign(self,url):
        if "@" in url:
            at = 1
        else:
            at = 0
        return at

    def getLength(self,url):
        if len(url) < 45:
            length = 0
        else:
            length = 1
        return length

    def getDepth(self,url):
        s = urlparse(url).path.split('/')
        depth = 0
        for j in range(len(s)):
            if len(s[j]) != 0:
                depth = depth + 1
        return depth

    def redirection(self,url):
        pos = url.rfind('//')
        if pos > 6:
            if pos > 7:
                return 1
            else:
                return 0
        else:
            return 0

    def httpDomain(self,url):
        # print(url)
        domain = urlparse(url).netloc
        # print(domain)
        if 'https' in url:
            return 0
        else:
            return 1


    def tinyURL(self,url):
        match = re.search(self.shortening_services, url)
        if match:
            return 1
        else:
            return 0

    def prefixSuffix(self,url):

        if '-' in url:
            print(url)
            return 1  # phishing
        else:
            return 0  # legitimate

    def web_traffic(self,url):
        try:
            url = urllib.parse.quote(url)
            rank = \
                BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(),
                              "xml").find("REACH")['RANK']
            rank = int(rank)
        except TypeError:
            return 1
        if rank < 100000:
            return 1
        else:
            return 0

    def iframe(self,response):
        if response == "":
            return 1
        else:
            if re.findall(r"[<iframe>|<frameBorder>]", response.text):
                return 0
            else:
                return 1

    def mouseOver(self,response):
        if response == "":
            return 1
        else:
            if re.findall("<script>.+onmouseover.+</script>", response.text):
                return 1
            else:
                return 0

    def rightClick(self,response):
        if response == "":
            return 1
        else:
            if re.findall(r"event.button ?== ?2", response.text):
                return 0
            else:
                return 1

    def forwarding(self,response):
        if response == "":
            return 1
        else:
            if len(response.history) <= 2:
                return 0
            else:
                return 1

    # Function to extract features
    # There are 15 features extracted from the dataset
    def featureExtractions(self,url):
        detection = DETECTION()
        features = [detection.getDomain(url), detection.havingIP(url), detection.haveAtSign(url),
                    detection.getLength(url), detection.getDepth(url), detection.redirection(url),
                    detection.httpDomain(url), detection.prefixSuffix(url), detection.tinyURL(url)]
        # Address bar based features (9)

        # Domain based features (4)
        dns = 0
        try:
            domain_name = whois.whois(urlparse(url).netloc)
        except:
            dns = 1

        features.append(dns)
        #features.append(detection.web_traffic(url))


        # HTML & Javascript based features (4)
        try:
            response = requests.get(url)
        except:
            response = ""
        features.append(detection.iframe(response))
        features.append(detection.mouseOver(response))
        features.append(detection.rightClick(response))
        features.append(detection.forwarding(response))
        # features.append(label)

        return features
        # bob = featureExtractions('http://www.facebook.com/home/service')
        # print(bob)
