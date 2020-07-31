from django.urls import path
from . import api_views

app_name = 'api'
urlpatterns = [
    path('login/', api_views.APILoginView.as_view(), name='login'),
    path('logout/', api_views.APILogoutView.as_view(), name='logout'),
    path('signup/', api_views.APISignupView.as_view(), name='signup'),
    path('signup_management', api_views.APIUserManagementView.as_view(), name='user_management'),
    path('delete_user/', api_views.APIDeleteUserView.as_view(), name='delete_user'),
    path('user_management_user_list', api_views.APIUserManagementUserListView.as_view(),
         name='user_management_user_list'),
    path('get_teacher_group_list', api_views.APIGetTeacherGroupList.as_view(), name='get_teacher_group_list'),
    path('get_user_type', api_views.APIGetUserType.as_view(), name='get_user_type'),
    path('scenelist', api_views.APIGetSceneList.as_view(), name='get_scene_list'),
    path('add_new_scene', api_views.APIAddNewScene.as_view(), name='add_new_scene'),
    path('get_scene_inforamtion', api_views.APIGetSceneInformation.as_view(), name='get_scene_information'),
    path('save_scene_information', api_views.APISaveSceneInformation.as_view(), name='save_scene_information'),
]
