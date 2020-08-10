from django.urls import path
from . import api_views

app_name = 'api'
urlpatterns = [

    # 登陆
    path('login/', api_views.APILoginView.as_view(), name='login'),

    # 登出
    path('logout/', api_views.APILogoutView.as_view(), name='logout'),

    # 提交注册信息
    path('account/signup/', api_views.APISignupView.as_view(), name='signup'),

    # 获取用户类型为artist的列表，用于设置item的author
    path('account/artist_list/', api_views.APIGetArtistList.as_view(), name='get_artist_list'),

    # 更改用户是否激活的属性
    path('account/signup_management/', api_views.APIUserManagementView.as_view(), name='user_management'),

    # 删除用户
    path('account/delete_user/', api_views.APIDeleteUserView.as_view(), name='delete_user'),

    # 获取课操作的用户列表
    path('account/user_management_user_list/', api_views.APIUserManagementUserListView.as_view(), name='user_management_user_list'),

    # 获取一个组列表，teacher类型用户注册时需要选择一个组
    path('account/scenelist', api_views.APIGetSignupSceneList.as_view(), name='signup_scene_list'),

    path('account/exhibitionlist', api_views.APISignupExhibitionList.as_view(), name='signup_exhibition_list'),

    # 获取当前已经登陆的用户的类型，返回artist/teacher/stuff/superuser
    path('account/user_type/', api_views.APIGetUserType.as_view(), name='get_user_type'),
    
    # Exhibition list
    path('exhibitionlist/', api_views.APIExhibitionList.as_view(), name='get_exhibition_list'),

    # Exhibition Add
    path('exhibitionadd/', api_views.APIExhibitionAdd.as_view(), name='exhibition_add'),

    # Exhibition Delete
    path('exhibition/<int:exhibition_id>/', api_views.APIExhibitionDelete.as_view(), name='delete_exhibition'),
    
    # Exhibition Info
    path('exhibition/<int:exhibition_id>/info/', api_views.APIExhibitionInfo.as_view(), name='exhibition_info'),

    # 获取场景列表
    path('scenelist/', api_views.APIGetSceneList.as_view(), name='get_scene_list'),

    # 添加新场景
    path('sceneadd/', api_views.APIAddNewScene.as_view(), name='add_new_scene'),

    # 删除场景
    path('scene/<int:scene_id>/', api_views.APISceneDelete.as_view(), name='delete_scene'),

    # 获取/修改场景的信息
    path('scene/<int:scene_id>/info/', api_views.APISceneInformation.as_view(), name='scene_information'),

    # 下载/上传场景模型文件
    path('scene/<int:scene_id>/file/', api_views.APISceneFile.as_view(), name='upload_scene'),

    # 获取该场景下所有item
    path('scene/<int:scene_id>/itemlist/', api_views.APIGetItemList.as_view(), name='get_item_list'),

    # 往该场景下添加itme
    path('scene/<int:scene_id>/itemadd/', api_views.APIAddItem.as_view(), name='add_item'),

    # 删除该item
    path('item/<int:item_id>/', api_views.APIDeleteItem.as_view(), name='item_delete'),

    # 获取/修改该item信息
    path('item/<int:item_id>/info/', api_views.APIItemInformation.as_view(), name='item_information'),

    # 下载/上传item模型文件
    path('item/<int:item_id>/file/', api_views.APIItemFile.as_view(), name='item_file'),
]
