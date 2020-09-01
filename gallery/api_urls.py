from django.urls import path
from . import api_views

app_name = 'api'
urlpatterns = [

    # 登陆
    path('login/', api_views.APILoginView.as_view(), name='login'),

    # 登出
    path('logout/', api_views.APILogoutView.as_view(), name='logout'),

    # 提交注册信息
    path('signup/', api_views.APISignupView.as_view(), name='signup'),

    # 获取所有注册申请
    path('signuprequestlist/', api_views.APIAllSignupRequestListView.as_view(), name='all_signup_request_list'),

    # 获取特定exhibition下的注册申请，并根据权限过滤
    path('exhibition/<int:exhibition_id>/signuprequestlist/', api_views.APISignupRequestListView.as_view(), name='signup_request_list'),

    # 处理注册申请
    path('signuprequest/<int:signuprequest_id>/', api_views.APISignupRequestView.as_view(), name='signup_request'),

    # 所有用户列表
    path('userlist/', api_views.APIAllUserList.as_view(), name='all_user_list'),

    # 删除用户(superuser)
    path('user/<int:user_id>/', api_views.APIUserDeleteView.as_view(), name='delete_user'),

    # 获取特定用户的用户信息
    # 因为不指定exhibition，所以user_type字段只有superuser或空字符串
    path('user/<int:user_id>/info/', api_views.APIUserView.as_view(), name='user_information'),
    
    # Exhibition list
    path('exhibitionlist/', api_views.APIExhibitionList.as_view(), name='get_exhibition_list'),

    # Exhibition Add
    path('exhibitionadd/', api_views.APIExhibitionAdd.as_view(), name='exhibition_add'),

    # 对scene item tool的操作都带exhibition_id的原因是
    # 用户在不同exhibition里有不同的user_type
    # 所以要指定exhibition用来检查权限

    # Exhibition Delete
    path('exhibition/<int:exhibition_id>/', api_views.APIExhibitionDelete.as_view(), name='delete_exhibition'),
    
    # Exhibition Info
    path('exhibition/<int:exhibition_id>/info/', api_views.APIExhibitionInfo.as_view(), name='exhibition_info'),

    # 获取scenelist
    path('scenelist/', api_views.APISceneList.as_view(), name='get_scene_list'),

    # 添加新场景
    path('sceneadd/', api_views.APISceneAdd.as_view(), name='add_new_scene'),

    # 删除场景
    path('scene/<int:scene_id>/', api_views.APISceneDelete.as_view(), name='delete_scene'),

    # 获取/修改场景的信息
    path('scene/<int:scene_id>/info/', api_views.APISceneInformation.as_view(), name='scene_information'),

    # 下载/上传场景模型文件
    path('scene/<int:scene_id>/file/', api_views.APISceneFile.as_view(), name='upload_scene'),

    # 获取该展览下所有item
    path('exhibition/<int:exhibition_id>/itemlist/', api_views.APIGetItemList.as_view(), name='get_item_list'),


    # 往该展览下添加itme
    path('exhibition/<int:exhibition_id>/itemadd/', api_views.APIItemAdd.as_view(), name='add_item'),

    # 删除该item
    path('exhibition/<int:exhibition_id>/item/<int:item_id>/', api_views.APIDeleteItem.as_view(), name='item_delete'),

    # 获取/修改该item信息
    path('exhibition/<int:exhibition_id>/item/<int:item_id>/info/', api_views.APIItemInformation.as_view(), name='item_information'),

    # 下载/上传item模型文件
    path('exhibition/<int:exhibition_id>/item/<int:item_id>/file/', api_views.APIItemFile.as_view(), name='item_file'),

    # get item list base on scene
    path('exhibition/<int:exhibitioin_id>/toollist/', api_views.APIGetToolList.as_view(), name='get_tool_list'),

    # add new tool
    path('exhibition/<int:exhibition_id>/tooladd/', api_views.APIToolAdd.as_view(), name='add_tool'),

    # get / change tool information
    path('exhibition/<int:exhibition_id>/tool/<int:tool_id>/info/', api_views.APIToolInfo.as_view(), name='tool_information'),

    # delete tool
    path('exhibition/<int:exhibition_id>/tool/<int:tool_id>/', api_views.APIToolDelete.as_view(), name='delete_tool'),
]
