from django.shortcuts import render, reverse
from django.http import HttpResponseRedirect
from django.views import View
from django.contrib.auth.models import User


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


class AllSceneManagementView(View):

    @staticmethod
    def get(request):
        view_dict = {
            'title': "All Scene Management"
        }
        return render(request, 'gallery/dashboard/all_scene_management.html', view_dict)
