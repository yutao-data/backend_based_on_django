from django.urls import path
from . import api_views


urlpatterns = [
    path('login/', api_views.APILoginView.as_view(), name='api_login'),
    path('logout/', api_views.APILogoutView.as_view(), name='api_logout'),
    path('signup/', api_views.APISignupView.as_view(), name='api_signup'),
]
