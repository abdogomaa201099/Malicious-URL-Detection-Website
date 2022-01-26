from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

class SignUpForm(UserCreationForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args,**kwargs)
        self.fields['username'].widget.attrs.update({
            'type': 'text',
            'required':'',
            'id': 'username',
            'name': 'username',
            'class' : 'form-control form-control-lg',
        })
        self.fields['email'].widget.attrs.update({
            'type': 'email',
            'required': '',
            'id': 'email',
            'name': 'email',
            'class': 'form-control form-control-lg',
        })
        self.fields['password1'].widget.attrs.update({
            'type': 'password',
            'required': '',
            'id': 'password1',
            'name': 'password1',
            'class': 'form-control form-control-lg',
        })
        self.fields['password2'].widget.attrs.update({
            'type': 'password',
            'required': '',
            'id': 'password2',
            'name': 'password2',
            'class': 'form-control form-control-lg',
        })


    class Meta:
        model=User
        fields = ['username', 'email', 'password1', 'password2']

