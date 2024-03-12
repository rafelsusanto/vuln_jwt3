from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.my_login_view, name='login'),
    path('', views.home_page, name='home_page'),
    path('admin/', views.admin_page, name='admin_page'),
    path('logout/', views.logout, name='logout'),
    path('jwks.json', views.jwks_show, name='jwks'),
]