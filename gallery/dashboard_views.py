from django.shortcuts import render, reverse
from django.http import HttpResponseRedirect
from django.views import View
from django.contrib.auth.models import User
from .api_views import get_user_type
from .models import Scene


# 管理面板Dashboard视图
class DashboardView(View):

    @staticmethod
    def get(request):
        view_dict = {
            'title': 'Dashboard',
        }
        not_active_user_list = []
        # 检查是否有用户等待注册审批
        for user in User.objects.all():
            if not user.is_active:
                not_active_user_list.append(user)
        # 如果有，则添加到字典里传递到视图中
        if not_active_user_list:
            view_dict['not_active_user_list'] = not_active_user_list
        return render(request, 'gallery/dashboard/index.html', view_dict)


# 管理用户的视图
class UserManagement(View):

    @staticmethod
    def get(request):
        view_dict = {
            'title': 'User Management',
        }
        # 正常返回页面
        return render(request, 'gallery/dashboard/user_management.html', view_dict)


# 所有 scene 的管理视图
class AllSceneManagementView(View):

    @staticmethod
    def get(request):
        view_dict = {
            'title': 'All Scene Management',
        }
        return render(request, 'gallery/dashboard/all_scene_management.html', view_dict)


# 单个 scene 的管理视图
class SceneManagementView(View):

    @staticmethod
    def get(request):
        view_dict = {
            'title': 'Scene Management',
        }
        return render(request, 'gallery/dashboard/scene_management.html', view_dict)


# 全部item的管理视图
class AllItemManagementView(View):

    @staticmethod
    def get(request):
        view_dict = {
            'title': 'All Item Management',
        }
        return render(request, 'gallery/dashboard/all_item_management.html', view_dict)


# 单个item的管理视图
class ItemManagementView(View):

    @staticmethod
    def get(request):
        view_dict = {
            'title': 'Item Management',
        }
        return render(request, 'gallery/dashboard/item_management.html', view_dict)


# All Exhibition management
class AllExhibitionManagement(View):

    @staticmethod
    def get(request):
        view_dict = {
            'title': 'Exhibition Management',
        }
        return render(request, 'gallery/dashboard/all_exhibition_management.html', view_dict)



