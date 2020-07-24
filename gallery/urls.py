from django.urls import include, path
from . import views
from . import api_urls

app_name = 'gallery'
urlpatterns = [
    path('api/', include('gallery.api_urls')),
    path('', views.IndexView.as_view(), name='index'),
    path('login/', views.LoginView.as_view(), name='login'),
    path('signup/', views.SignupView.as_view(), name='signup'),
    path('dashboard/', views.DashboardView.as_view(), name='dashboard')
]
