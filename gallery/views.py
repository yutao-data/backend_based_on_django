from django.shortcuts import render
from django.views import View
from django.contrib.auth.models import User
import copy


BASIC_TEXT = {
    'site_name': 'Virtual Gallery Tour System',

}


# 首页视图
class IndexView(View):

    @staticmethod
    def get(request):
        return render(request, 'gallery/index.html', BASIC_TEXT)


# 登陆页视图，继承自django的auth组件
class LoginView(View):

    @staticmethod
    def get(request):
        return render(request, 'gallery/login.html', BASIC_TEXT)


# 注册视图
class SignupView(View):

    @staticmethod
    def get(request):
        return render(request, 'gallery/signup.html', BASIC_TEXT)


# 管理面板Dashboard视图
class DashboardView(View):

    @staticmethod
    def get(request):
        view_dict = {}
        not_active_user_list = []
        # 检查是否有用户等待注册审批
        for user in User.objects.all():
            if not user.is_active:
                not_active_user_list.append(user.username)
        # 如果有，则添加到字典里传递到视图中
        if not_active_user_list:
            view_dict['not_active_user_list'] = not_active_user_list
        return render(request, 'gallery/dashboard/base.html', view_dict)
