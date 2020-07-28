import json
from django.views import View
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.forms import Form, CharField, IntegerField, NullBooleanField
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from .error import Error, JsonError, FormValidError, AuthenticateError, APIFormNotDefine
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
    # 占位符避免no attribute 错误
    MyForm = None
    # 是否需要表单
    need_form = True

    def post(self, requests):
        try:
            # 使用json解码
            data = json.loads(requests.body)
            # 表单未定义
            if not self.MyForm and self.need_form:
                raise APIFormNotDefine
            # 如果不需要表单则不验证表单，直接返回视图
            if not self.need_form:
                return self.my_post(requests)
            # 验证表单
            form = self.MyForm(data)
            if not form.is_valid():
                raise FormValidError
            cleaned_data = form.clean()
            # 调用真实的my_post函数处理请求
            return self.my_post(requests, cleaned_data)

        # 统一的错误处理，减少代码重复
        # To do: 细化错误处理
        except Error as e:
            return JsonResponse({
                'error_type': str(e.__class__.__name__),  # 使用类名作为错误类型
                'error_message': str(e)  # 调用e的__str__()方法，获取错误详细解释
            }, status=e.status)
        # 捕获未定义的错误
        except Exception as e:
            # 输出错误类型和错误信息到控制台
            print('%s: %s' % (str(type(e)), str(e)))
            return JsonResponse({
                'error_type': 'NotDefine Error: ' + str(type(e)),
                'error_message': str(e),
            }, status=500)


# 继承自定义的API视图
class APILoginView(APIView):
    class MyForm(Form):
        username = CharField(label='username')
        password = CharField(label='password')

    @staticmethod
    def my_post(request, cleaned_data):
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
    # 本视图不需要任何表单
    need_form = False

    @staticmethod
    def my_post(request):
        logout(request)
        request.session.flush()
        return get_success_response()


class APISignupView(APIView):
    class MyForm(Form):
        username = CharField(label='username')
        password = CharField(label='password')
        user_type = CharField(label='user_type')

    @staticmethod
    def my_post(request, cleaned_data):
        # 检查用户名是否被占用
        if len(User.objects.filter(username=cleaned_data['username'])) > 0:
            raise Error(message='Username has been taken', status=403)
        user = User.objects.create_user(
            username=cleaned_data['username'],
            password=cleaned_data['password'],
        )
        # 设置用户可活动状态为False等待审核
        user.is_active = False

        # 设置用户权限
        # 用户类型有四种: artist/teacher/stuff/superuser
        # 分别对应展品上传者/布展老师/展览管理员/站点管理员（超级用户user.is_superuser=true）
        user_type = cleaned_data['user_type']
        if user_type == 'artist':
            pass
        elif user_type == 'teacher':
            pass
        elif user_type == 'stuff':
            pass
        elif user_type == 'stuff':
            pass
        else:
            # 用户提交了未定义的类型，引发一个错误
            raise FormValidError

        user.save()
        return get_success_response()


class APIUserManagementView(APIView):
    class MyForm(Form):
        pk = IntegerField(label='pk')
        user_status = NullBooleanField(label='user_status')

    @staticmethod
    def my_post(request, cleaned_data):
        # 设置用户状态
        user = User.objects.get(pk=cleaned_data['pk'])
        user.is_active = cleaned_data['user_status']
        user.save()
        return get_success_response()


# 获取等待注册审核的用户信息
class APIUserManagementUserListView(APIView):
    need_form = False

    @staticmethod
    def my_post(request):
        user_list = []
        for user in User.objects.all():
            # 跳过管理员
            if user.is_superuser:
                continue
            user_list.append({
                'username': user.username,
                'pk': user.pk,
                'user_status': user.is_active,
            })
        return JsonResponse({'user_list': user_list})


class APIDeleteUserView(APIView):
    class MyForm(Form):
        pk = IntegerField(label='pk')

    @staticmethod
    def my_post(request, cleaned_data):
        user = User.objects.get(pk=cleaned_data['pk'])
        user.delete()
        return get_success_response()


class APIGetUserType(APIView):
    need_form = False

    @staticmethod
    def my_post(request):
        user_type = ''
        user_type_describe = ''
        # 从高权限到低权限检查
        if request.user.is_superuser:
            user_type = 'superuser'
        return JsonResponse({
            'user_type': user_type,
        })

