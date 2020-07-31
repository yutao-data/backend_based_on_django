import json
from django.views import View
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.forms import (
    Form,
    CharField,
    IntegerField,
    NullBooleanField,
    FileField,
)
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User, Group
from .error import (
    Error,
    JsonError,
    FormValidError,
    AuthenticateError,
    APIFormNotDefine,
    NoPermission,
)
from .models import Scene, Item
from guardian.shortcuts import assign_perm
from django.contrib.auth.decorators import login_required
# from rest_framework.views import View
# rest_framework是个什么鬼，权限写成数组不和guardian兼容
# 重写一堆方法写来写去403错也不爆
# 官方文档插拔方法没个锤子用
# 传的还不是django的HTTPResponse
# 坑
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

    def get(self, requests, *args, **kwargs):
        try:
            return self.my_get(requests, *args, **kwargs)
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

    def post(self, requests, *args, **kwargs):
        try:
            # 使用json解码
            data = json.loads(requests.body)
            # 表单未定义
            if not self.MyForm:
                raise APIFormNotDefine
            # 验证表单
            form = self.MyForm(data)
            if not form.is_valid():
                raise FormValidError
            cleaned_data = form.clean()
            # 调用真实的my_post函数处理请求
            return self.my_post(requests, cleaned_data, *args, **kwargs)

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
        return JsonResponse({
            'user_type': get_user_type(request),
        })


class APILogoutView(APIView):

    @staticmethod
    def my_get(request):
        logout(request)
        request.session.flush()
        return get_success_response()


class APISignupView(APIView):
    class MyForm(Form):
        username = CharField(label='username')
        password = CharField(label='password')
        user_type = CharField(label='user_type')
        teacher_group_pk = IntegerField(label='teacher_group_pk', required=False)

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
            # 普通用户artist不属于任何组，他们只有自己展品的object权限
            pass
        elif user_type == 'teacher':
            # 老师teacher属于scene.group组，该组拥有scene内所有item的object权限，和对应scene的object权限
            teacher_group_pk = cleaned_data['teacher_group_pk']
            group = Group.objects.get(pk=teacher_group_pk)
            group.user_set.add(user)
        elif user_type == 'stuff':
            # 策展管理员stuff拥有item和scene的全局权限，可以管理所有物体
            assign_perm('gallery.view_item', user)
            assign_perm('gallery.add_item', user)
            assign_perm('gallery.change_item', user)
            assign_perm('gallery.delete_item', user)
            assign_perm('gallery.view_scene', user)
            assign_perm('gallery.add_scene', user)
            assign_perm('gallery.change_scene', user)
            assign_perm('gallery.delete_scene', user)
        elif user_type == 'superuser':
            user.is_superuser = True
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

    @staticmethod
    def my_get(request):
        user_list = []
        for user in User.objects.all():
            # 跳过管理员
            if user.is_superuser:
                continue
            # 跳过匿名帐号
            if user.username == 'AnonymousUser':
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

    @staticmethod
    def my_get(request):
        user_type_describe = ''
        user_type = get_user_type(request)
        return JsonResponse({
            'user_type': user_type,
        })


# 获取用户类型
def get_user_type(request):
    # 从低权限到高权限检查
    user_type = 'artist'
    if request.user.has_perm('gallery.change_scene'):
        user_type = 'stuff'
    if request.user.groups.all():
        user_type = 'teacher'
    if request.user.is_superuser:
        user_type = 'superuser'
    return user_type


# 获取所有场景的用户组信息
class APIGetTeacherGroupList(APIView):

    @staticmethod
    def my_get(request):
        teacher_group_list = []
        for scene in Scene.objects.all():
            if scene.group:
                teacher_group = {
                    'pk': scene.group.pk,
                    'name': scene.name,
                }
                teacher_group_list.append(teacher_group)
        return JsonResponse({
            'teacher_group_list': teacher_group_list,
        })


class APIGetSceneList(APIView):

    @staticmethod
    def my_get(request):
        user_type = get_user_type(request)
        scene_list = []
        # 拒绝普通用户
        if user_type == 'artist':
            raise NoPermission
        if user_type == 'teacher':
            for scene in Scene.objects.all():
                if request.user.has_perm('gallery.change_scene', scene):
                    scene_list.append({
                        'pk': scene.pk,
                        'name': scene.name,
                        'file': scene.file.name,
                    })
        if user_type == 'stuff' or user_type == 'superuser':
            for scene in Scene.objects.all():
                scene_list.append({
                    'pk': scene.pk,
                    'name': scene.name,
                    'file': scene.file.name,
                })
        return JsonResponse({
            'scene_list': scene_list
        })


class APIAddNewScene(APIView):
    class MyForm(Form):
        scene_name = CharField(label='scene_name')

    @staticmethod
    def my_post(request, cleaned_data):
        scene_name = cleaned_data['scene_name']
        # 检查 scene_name 是否已经存在
        if len(Scene.objects.filter(name=scene_name)) > 0:
            raise Error(message='Scene name has been taken', status=403)
        if len(Group.objects.filter(name=scene_name)) > 0:
            raise Error(message='Scene permission group name has been taken.', status=403)

        group = Group.objects.create(name=scene_name)
        # 分配这个展厅的object权限到组里
        assign_perm('gallery.view_scene', group)
        assign_perm('gallery.change_scene', group)
        # assign_perm('gallery.add_scene', group)
        # assign_perm('gallery.delete_scene', group)
        group.save()

        scene = Scene.objects.create(name=scene_name, group=group)
        scene.save()

        return get_success_response()


# 获取单个Scene的详细信息
class APIGetSceneInformation(APIView):
    class MyForm(Form):
        pk = IntegerField(label='pk')

    @staticmethod
    def my_post(request, cleaned_data):
        pk = cleaned_data['pk']
        scene = Scene.objects.get(pk=pk)
        group = scene.group
        users = group.user_set.all()
        user_list = []
        for user in users:
            user_list.append({
                "username": user.username,
            })
        return JsonResponse({
            'scene': {
                'name': scene.name,
                'pk': scene.pk,
                'file': scene.file.name,
            },
            'user_list': user_list,
        })


# 保存单个Scene的详细信息
class APISaveSceneInformation(APIView):
    class MyForm(Form):
        pk = IntegerField(label='pk')
        name = CharField(label='name', required=False)

    @staticmethod
    def my_post(request, cleaned_data):
        pk = cleaned_data['pk']
        scene = Scene.objects.get(pk=pk)
        if cleaned_data.get('name') is not None:
            name = cleaned_data['name']
            scene.name = name

        scene.save()
        return get_success_response()

