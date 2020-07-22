import json
from django.views import View
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.forms import Form, CharField
from django.contrib.auth import authenticate, login, logout
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
            # 调用真实的my_post函数处理请求
            return self.my_post(requests)

        # 统一的错误处理，减少代码重复
        # To do: 细化错误处理
        except Error as e:
            return JsonResponse({
                'error_type': str(type(e)),
                'error_message': str(e)
            }, status=e.status)


# 继承自定义的API视图
class APILoginView(APIView):
    def my_post(self, request):
        class APILoginPostForm(Form):
            username = CharField()
            password = CharField()
        data = json.loads(request.body)
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
    def my_post(self, request):
        logout(request)
        request.session.flush()
        return get_success_response()

