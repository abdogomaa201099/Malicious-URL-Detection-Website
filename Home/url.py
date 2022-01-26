from django.contrib import admin
from django.urls import path, include
from . import views

urlpatterns = [
    path('',views.home, name='home'),
    path('pdf/', views.GeneratePdf.as_view(), name='showpdf'),
    path('show/<int:id>', views.GeneratePdfFromReports.as_view(), name='showpdffromreports'),
    path('reports/', views.reports, name='reports'),
    path('about/', views.about, name='about'),
    path('DeleteAccount/', views.DeleteAccount, name='DeleteAccount'),
    path('update/', views.update, name='update'),
    path('reports/DeleteReport/<int:id>', views.DeleteReport, name='DeleteReport'),
    path('realtimescanning', views.realtimescanning, name='realtimescanning'),
]
