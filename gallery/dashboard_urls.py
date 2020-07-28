from django.urls import include, path
from . import dashboard_views


app_name = 'dashboard'
urlpatterns = [
    path('', dashboard_views.DashboardView.as_view(), name='index'),
    path('signup_management/', dashboard_views.UserManagement.as_view(), name='user_management'),
    path('all_scene_management', dashboard_views.AllSceneManagementView.as_view(), name='all_scene_management'),
]
