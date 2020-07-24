from django.urls import include, path
from . import dashboard_views


app_name = 'dashboard'
urlpatterns = [
    path('', dashboard_views.DashboardView.as_view(), name='index'),
    path('signup_management/', dashboard_views.SignUpManagement.as_view(), name='signup_management'),
]
