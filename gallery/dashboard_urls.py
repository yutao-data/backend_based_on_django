from django.urls import include, path
from . import dashboard_views


app_name = 'dashboard'
urlpatterns = [
    path('', dashboard_views.DashboardView.as_view(), name='index'),
    path('signup_management/', dashboard_views.UserManagement.as_view(), name='user_management'),
    path('all_scene_management/', dashboard_views.AllSceneManagementView.as_view(), name='all_scene_management'),
    path('scene_management/', dashboard_views.SceneManagementView.as_view(), name='scene_management'),
    path('all_item_management', dashboard_views.AllItemManagementView.as_view(), name='all_item_management'),
    path('item_management', dashboard_views.ItemManagementView.as_view(), name='item_management'),
    path('all_exhibition_management/', dashboard_views.AllExhibitionManagement.as_view(), name='all_exhibition_management'),
    path('exhibition_management/', dashboard_views.ExhibitionManagement.as_view(), name='exhibition_management'),
]
