from django.contrib import admin
from django.urls import path, include
from . import views
from django.contrib.auth import views as vs

urlpatterns = [
    path('signup/', views.signup, name='signup'),
    path('logout/',vs.LogoutView.as_view(), name='logout'),
    path('login/', vs.LoginView.as_view(template_name='login.html'), name ='login'),
]
