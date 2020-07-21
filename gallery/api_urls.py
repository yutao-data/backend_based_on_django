from django.urls import path
from . import api_views


urlpatterns = [
    path('login/', api_views.APILoginView.as_view(), name='api_login')
]