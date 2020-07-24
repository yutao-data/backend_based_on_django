from django.shortcuts import render, reverse
from django.http import HttpResponseRedirect
from django.views import View
from django.contrib.auth import logout
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


# 简单的HTTP登出视图
class LogoutView(View):

    @staticmethod
    def get(request):
        logout(request)
        return HttpResponseRedirect(reverse('gallery:index'))
