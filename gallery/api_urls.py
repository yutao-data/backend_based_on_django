from django.urls import path
from . import api_views

app_name = 'api'
urlpatterns = [
    path('login/', api_views.APILoginView.as_view(), name='login'),
    path('logout/', api_views.APILogoutView.as_view(), name='logout'),
    path('signup/', api_views.APISignupView.as_view(), name='signup'),
    path('author_list/', api_views.APIGetArtistList.as_view(), name='get_artist_list'),
    path('signup_management/', api_views.APIUserManagementView.as_view(), name='user_management'),
    path('delete_user/', api_views.APIDeleteUserView.as_view(), name='delete_user'),
    path('user_management_user_list/', api_views.APIUserManagementUserListView.as_view(), name='user_management_user_list'),
    path('get_teacher_group_list/', api_views.APIGetTeacherGroupList.as_view(), name='get_teacher_group_list'),
    path('get_user_type/', api_views.APIGetUserType.as_view(), name='get_user_type'),
    path('scenelist/', api_views.APIGetSceneList.as_view(), name='get_scene_list'),
    path('sceneadd/', api_views.APIAddNewScene.as_view(), name='add_new_scene'),
    path('scene/<int:scene_id>/', api_views.APISceneDelete.as_view(), name='delete_scene'),
    path('scene/<int:scene_id>/info/', api_views.APISceneInformation.as_view(), name='scene_information'),
    path('scene/<int:scene_id>/file/', api_views.APISceneFile.as_view(), name='upload_scene'),
    path('scene/<int:scene_id>/itemlist/', api_views.APIGetItemList.as_view(), name='get_item_list'),
    path('scene/<int:scene_id>/itemadd/', api_views.APIAddItem.as_view(), name='add_item'),
    path('item/<int:item_id>/info/', api_views.APIItemInformation.as_view(), name='item_information'),
]
