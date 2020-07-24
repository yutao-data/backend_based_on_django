from django.urls import path
from . import api_views

app_name = 'api'
urlpatterns = [
    path('login/', api_views.APILoginView.as_view(), name='login'),
    path('logout/', api_views.APILogoutView.as_view(), name='logout'),
    path('signup/', api_views.APISignupView.as_view(), name='signup'),
    path('signupmanagement', api_views.APISignUpManagementView.as_view(), name='signup_management'),
]
