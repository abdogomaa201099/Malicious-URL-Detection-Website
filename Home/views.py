from django.shortcuts import render, redirect
import joblib
from io import BytesIO
from django.http import HttpResponse
from django.template.loader import get_template
from django.views.generic import View
import datetime
from xhtml2pdf import pisa
import validators
import re
from . import models
import matplotlib.pyplot as plt
import numpy as np
import io
import urllib, base64
import os.path
from sklearn.base import BaseEstimator, TransformerMixin
import pickle
import pandas as pd
from typing import Optional
from collections import defaultdict as Dict
from urllib.parse import urlparse
import tldextract
from nltk.tokenize import RegexpTokenizer
from django.contrib.auth.models import User
from django.contrib import messages
from Accounts.forms import SignUpForm
from scapy.all import sniff
import socket
# Create your views here.


class Converter(BaseEstimator, TransformerMixin):
    def fit(self, x, y=None):
        return self

    def transform(self, data_frame):
        return data_frame.values.ravel()

class CustomUnpickler(pickle.Unpickler):

    def find_class(self, module, name):
        if name == 'Converter':

            return Converter
        return super().find_class(module, name)



def home(request):
    #model=joblib.load('fmodel.sav')
    model = CustomUnpickler(open('fffmodel.sav', 'rb')).load()
    url=request.POST.get('url')
    prediction=None
    request.session['url']=None
    request.session['user']=None
    request.session['id'] = None
    request.session['badprob'] = None
    request.session['goodprob'] = None



    regex = re.compile(
    r'^(|(?:http|ftp)s?://)'  # http:// or https://
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
    r'localhost|'  # localhost...
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
    r'(?::\d+)?'  # optional port
    r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    if request.method=='POST':
        if re.match(regex, url) is not None:
            request.session['url'] = url
            request.session['user'] = request.user.username
            request.session['id'] = request.user.id
            request.session['badprob'] = model.predict_proba(prepare(url))[:, 0].tolist()
            request.session['goodprob'] = model.predict_proba(prepare(url))[:, 1].tolist()

            prediction = model.predict(prepare(url))
        else:
            messages.error(request, 'Please Enter A Valid URL...')
    else:
        messages.error(request, 'Please Enter A Valid URL...')

    return render(request, 'home.html', {'prediction':prediction})


def realtimescanning(request):
    model = CustomUnpickler(open('fffmodel.sav', 'rb')).load()
    regex = re.compile(
        r'^(|(?:http|ftp)s?://)'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    urls = listOfRealTimeURLs()
    urlslist=[]
    predictions=[]
    ipch=re.compile("\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}")
    for url in urls:
        if re.fullmatch(regex, url) :
            if 'local' not in url:
                if 'cdn' not in url:
                    if 'cloudfront' not in url:
                        if not re.fullmatch(ipch,url):
                            if url not in urlslist:
                                urlslist.append(url)
                                predictions.append([model.predict(prepare(url)),url])

    return render(request, 'realtimescanning.html', {'predictions':predictions})

def listOfRealTimeURLs():
    lis = []
    count = 0
    while count < 100:
        pktl = sniff(iface="Wi-Fi", count=1)
        count = count + 1
        for pkt in pktl:
            try:
                if 'DNS' in pkt.summary():
                    packet = str(pkt.summary())
                    start = packet.find('"') + 1
                    packet = packet[start:]
                    if "b'" in packet:
                        start = packet.find("b'") + 2
                        packet = packet[start:]
                    else:
                        start = packet.find("'") + 1
                        packet = packet[start:]
                    end = packet.find("'")
                    packet = packet[:end]
                    l = len(packet)
                    if packet[l - 1:] is '"' or '.':
                        packet = packet[:l - 1]
                    if 'Ether / IP / UDP /' not in packet:
                        lis.append(packet)
            except:
                raise
    return lis


def render_to_pdf(template_src, context_dict={}):
    template = get_template(template_src)
    html  = template.render(context_dict)
    result = BytesIO()
    pdf = pisa.pisaDocument(BytesIO(html.encode("ISO-8859-1")), result)
    if not pdf.err:
        return HttpResponse(result.getvalue(), content_type='application/pdf')
    return None

class GeneratePdf(View):
    def get(self, request, *args, **kwargs):
        nrep = models.Report.objects.create(url=request.session['url'], uid=request.session['id'], prop_good=request.session['goodprob'][0], prop_bad=request.session['badprob'][0])
        nrep.save()

        y = np.array([request.session['goodprob'][0], request.session['badprob'][0]])
        mylabels = ["Secure", "Malicious"]
        fig, ax = plt.subplots()
        myexplode = [0.2, 0,]
        s = ax.pie(y, labels=mylabels, shadow = True, explode = myexplode)
        plt.legend()
        path = os.path.join('c://Users/abdog/Desktop/Django_Projects/PSM/media', str(nrep.id))
        os.mkdir(path)
        path = os.path.join(path, 'image.png')
        fig.savefig(path)
        res='Malicious'
        if request.session['goodprob'][0]>request.session['badprob'][0]:
            res='Secure'
        data = {
            'today': datetime.date.today(),
            'url': request.session['url'],
            'username': request.session['user'],
            'UserID':request.session['id'] ,
            'report_id': nrep.id,
            'good_prob':request.session['goodprob'][0],
            'bad_prob': request.session['badprob'][0],
            'path':path,
            'res':res,
        }
        pdf = render_to_pdf('report.html', data)

        return pdf


def reports(request):
    userid=request.user.id
    reportlist=models.Report.objects.filter(uid=userid)


    return render(request,'reports.html',{'reportlist':reportlist})

def about(request):

    return render(request, 'about.html')


def DeleteAccount(request):
    id=request.user.id
    user=User.objects.get(id=id)
    user.delete()
    return redirect('../')

def DeleteReport(request , id):
    report=models.Report.objects.filter(id=id)
    report.delete()
    return redirect('../')


def update(request):
    form = SignUpForm()
    if request.method=='POST':
        form = SignUpForm(data=request.POST, instance=request.user)
        if form.is_valid():
            user = form.save(commit=False)
            user.save()
            messages.success(request, 'Form submission successful')
        else:
            messages.error(request, 'Form submission unsuccessful')
    return render(request,'update.html' ,{'form':form})



class GeneratePdfFromReports(View):

    def get(self, request, *args, **kwargs):
        id = self.kwargs['id']
        path = os.path.join('c://Users/abdog/Desktop/Django_Projects/PSM/media', str(id))
        id=models.Report.objects.get(id=id)
        res = 'Malicious'
        if request.session['goodprob'][0] > request.session['badprob'][0]:
            res = 'Secure'
        path = os.path.join(path, 'image.png')
        data = {
            'today': datetime.date.today(),
            'url': id.url,
            'username': request.user.username,
            'UserID':request.user.id ,
            'report_id': id.id,
            'good_prob':id.prop_good,
            'bad_prob': id.prop_bad,
            'path':path,
            'res':res,

        }
        pdf = render_to_pdf('report.html', data)

        return pdf




def prepare(url):
    url = pd.DataFrame({'url': url}, index=[1])

    def parse_url(url: str) -> Optional[Dict[str, str]]:
        no_scheme = not url.startswith('https://') and not url.startswith('http://')
        if no_scheme:
            parsed_url = urlparse(f"http://{url}")
            return {
                "scheme": None,  # not established a value for this
                "netloc": parsed_url.netloc,
                "path": parsed_url.path,
                "params": parsed_url.params,
                "query": parsed_url.query,
                "fragment": parsed_url.fragment,
            }
        else:
            parsed_url = urlparse(url)
            return {
                "scheme": parsed_url.scheme,
                "netloc": parsed_url.netloc,
                "path": parsed_url.path,
                "params": parsed_url.params,
                "query": parsed_url.query,
                "fragment": parsed_url.fragment,
            }

    url["parsed_url"] = url.url.apply(parse_url)

    url = pd.concat([
        url.drop(['parsed_url'], axis=1),
        url['parsed_url'].apply(pd.Series)], axis=1)

    url = url[~url.netloc.isnull()]

    url["length"] = url.url.str.len()

    url["tld"] = url.netloc.apply(lambda nl: tldextract.extract(nl).suffix)
    url['tld'] = url['tld'].replace('', 'None')

    url["is_ip"] = url.netloc.str.fullmatch(r"\d+\.\d+\.\d+\.\d+")

    url['domain_hyphens'] = url.netloc.str.count('-')
    url['domain_underscores'] = url.netloc.str.count('_')
    url['path_hyphens'] = url.path.str.count('-')
    url['path_underscores'] = url.path.str.count('_')
    url['slashes'] = url.path.str.count('/')

    url['full_stops'] = url.path.str.count('.')

    def get_num_subdomains(netloc: str) -> int:
        subdomain = tldextract.extract(netloc).subdomain
        if subdomain == "":
            return 0
        return subdomain.count('.') + 1

    url['num_subdomains'] = url['netloc'].apply(lambda net: get_num_subdomains(net))

    tokenizer = RegexpTokenizer(r'[A-Za-z]+')

    def tokenize_domain(netloc: str) -> str:
        split_domain = tldextract.extract(netloc)
        no_tld = str(split_domain.subdomain + '.' + split_domain.domain)
        return " ".join(map(str, tokenizer.tokenize(no_tld)))

    url['domain_tokens'] = url['netloc'].apply(lambda net: tokenize_domain(net))

    url['path_tokens'] = url['path'].apply(lambda path: " ".join(map(str, tokenizer.tokenize(path))))

    url.drop('url', axis=1, inplace=True)
    url.drop('scheme', axis=1, inplace=True)
    url.drop('netloc', axis=1, inplace=True)
    url.drop('path', axis=1, inplace=True)
    url.drop('params', axis=1, inplace=True)
    url.drop('query', axis=1, inplace=True)
    url.drop('fragment', axis=1, inplace=True)

    return url