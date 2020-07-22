import json
from django.views import View
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.forms import Form, CharField
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from .error import Error, JsonError, FormValidError, AuthenticateError
from django.contrib.auth.decorators import login_required

MAX_CHAR_LENGTH = 32


# 返回一个状态码200没啥内容的Json用于表示成功
def get_success_response(message='Success'):
    return JsonResponse({
        'message': message
    }, status=200)


# 自定义的API View类，减少代码量
@method_decorator(csrf_exempt, 'dispatch')
class APIView(View):
    def post(self, requests):
        try:
            # 使用json解码
            data = json.loads(requests.body)
            # 调用真实的my_post函数处理请求
            return self.my_post(requests, data)

        # 统一的错误处理，减少代码重复
        # To do: 细化错误处理
        except Error as e:
            return JsonResponse({
                'error_type': str(e.__class__.__name__),  # 使用类名作为错误类型
                'error_message': str(e)  # 调用e的__str__()方法，获取错误详细解释
            }, status=e.status)


# 继承自定义的API视图
class APILoginView(APIView):
    @staticmethod
    def my_post(request, data):
        class APILoginPostForm(Form):
            username = CharField()
            password = CharField()
        form = APILoginPostForm(data)
        if not form.is_valid():
            raise FormValidError
        cleaned_data = form.clean()
        user = authenticate(
            username=cleaned_data['username'],
            password=cleaned_data['password'],
        )
        if user is None:
            raise AuthenticateError()
        logout(request)
        login(request, user)
        return get_success_response()


class APILogoutView(APIView):
    @staticmethod
    def my_post(request, data):
        logout(request)
        request.session.flush()
        return get_success_response()


class APISignupView(APIView):
    @staticmethod
    def my_post(request, data):
        class APISignupPostForm(Form):
            username = CharField()
            password = CharField()
        form = APISignupPostForm(data)
        if not form.is_valid():
            raise FormValidError
        cleaned_data = form.clean()
        # 检查用户名是否被占用
        if len(User.objects.filter(username=cleaned_data['username'])) > 0:
            raise Error(message='Username has been taken', status=403)
        user = User.objects.create_user(
            username=cleaned_data['username'],
            password=cleaned_data['password'],
        )
        # 设置用户可活动状态为False等待审核
        user.is_active = False
        user.save()
        return get_success_response()
