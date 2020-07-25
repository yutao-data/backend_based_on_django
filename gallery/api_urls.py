from django.urls import path
from . import api_views

app_name = 'api'
urlpatterns = [
    path('login/', api_views.APILoginView.as_view(), name='login'),
    path('logout/', api_views.APILogoutView.as_view(), name='logout'),
    path('signup/', api_views.APISignupView.as_view(), name='signup'),
    path('signup_management', api_views.APISignUpManagementView.as_view(), name='signup_management'),
    path('delete_user/', api_views.APIDeleteUserView.as_view(), name='delete_user'),
    path('signup_management_user_list', api_views.APISignUpManagementUserListView.as_view(),
         name='signup_management_user_list'),
]
