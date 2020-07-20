from django.urls import include, path
from . import views


app_name = 'gallery'
urlpatterns = [
    path('', views.IndexView.as_view(), name='index'),
    path('login/', views.LoginView.as_view(), name='login')
]
