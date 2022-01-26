import json
import urllib
from django.conf import settings
from django.shortcuts import render, redirect
from django.contrib.auth import login as auth_log
from .forms import SignUpForm
from django.contrib import messages

# Create your views here.
def signup(request):
    form =SignUpForm()
    if request.method=='POST':
        form=SignUpForm(request.POST)
        if form.is_valid():
            print("form is valid")

            ''' Begin reCAPTCHA validation '''
            recaptcha_response = request.POST.get('g-recaptcha-response')
            url = 'https://www.google.com/recaptcha/api/siteverify'
            values = {
                'secret': settings.RECAPTCHA_PRIVATE_KEY,
                'response': recaptcha_response
            }
            data = urllib.parse.urlencode(values).encode()
            req = urllib.request.Request(url, data=data)
            response = urllib.request.urlopen(req)
            result = json.loads(response.read().decode())
            ''' End reCAPTCHA validation '''




            user = form.save()
            auth_log(request,user)
            return redirect('home')
        else:
            print("Error 404...!")
    return render(request, 'signup.html', {'form':form})