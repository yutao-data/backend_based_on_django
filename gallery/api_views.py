import json
import os.path
from backend_based_on_django.settings import MEDIA_ROOT
from django.views import View
from django.http import JsonResponse, FileResponse
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
    use_form = True

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

    def delete(self, request, *args, **kwargs):
        try:
            return self.my_del(request, *args, **kwargs)
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
            if not self.use_form:
                return self.my_post(requests, data, *args, **kwargs)
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
        teacher_group_id = IntegerField(label='teacher_group_id', required=False)

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
            teacher_group_id = cleaned_data['teacher_group_id']
            group = Group.objects.get(pk=teacher_group_id)
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
        id = IntegerField(label='id')
        user_status = NullBooleanField(label='user_status')

    @staticmethod
    def my_post(request, cleaned_data):
        # 设置用户状态
        user = User.objects.get(pk=cleaned_data['id'])
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
                'id': user.id,
                'user_status': user.is_active,
            })
        return JsonResponse({'user_list': user_list})


class APIDeleteUserView(APIView):
    class MyForm(Form):
        id = IntegerField(label='id')

    @staticmethod
    def my_post(request, cleaned_data):
        user = User.objects.get(pk=cleaned_data['id'])
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
                    # 实际选择的是组
                    # 显示的是Scene名
                    'id': scene.group.pk,
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
                        'id': scene.pk,
                        'name': scene.name,
                        'file': scene.file.name,
                    })
        if user_type == 'stuff' or user_type == 'superuser':
            for scene in Scene.objects.all():
                scene_list.append({
                    'id': scene.pk,
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

        return JsonResponse({
            "scene": {
                "name": scene.name,
                "id": scene.pk,
            }
        })


# 获取单个Scene的详细信息
class APISceneInformation(APIView):

    @staticmethod
    def my_get(request, scene_id):
        scene = Scene.objects.get(pk=scene_id)
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
                'id': scene.pk,
                'file': scene.file.name,
            },
            'user_list': user_list,
        })

    class MyForm(Form):
        id = IntegerField(label='id')
        name = CharField(label='name', required=False)

    @staticmethod
    def my_post(request, cleaned_data, scene_id):
        scene = Scene.objects.get(pk=scene_id)
        if cleaned_data.get('name') is not None:
            name = cleaned_data['name']
            scene.name = name

        scene.save()
        return get_success_response()


@method_decorator(csrf_exempt, 'dispatch')
class APISceneFile(View):

    @staticmethod
    def post(request, scene_id):
        file = request.FILES.get('file')
        data = request.POST.get('data')
        scene = Scene.objects.get(pk=scene_id)
        scene.file = file
        scene.save()
        return JsonResponse({
            "scene": {
                "name": scene.name,
                "id": scene.pk,
                "file": scene.file.name,
            }
        })

    @staticmethod
    def get(request, scene_id):
        scene = Scene.objects.get(pk=scene_id)
        f_p = os.path.join(MEDIA_ROOT, scene.file.name)
        f = open(f_p, 'rb')
        return FileResponse(f)


class APISceneDelete(APIView):

    @staticmethod
    def my_del(request, scene_id):
        scene = Scene.objects.get(pk=scene_id)
        group = scene.group
        group.delete()
        scene.delete()
        return get_success_response()


class APIGetItemList(APIView):

    @staticmethod
    def my_get(request, scene_id):
        item_list = []
        scene = Scene.objects.get(pk=scene_id)
        for item in Item.objects.filter(scene=scene):
            if request.user.has_perm('gallery.change_item', item):
                item_list.append(get_item_information(item))
        return JsonResponse({
            'item_list': item_list,
        })


class APIItemInformation(APIView):
    use_form = False

    @staticmethod
    def my_get(request, item_id):
        item = Item.objects.get(pk=item_id)
        return JsonResponse({
            'item': get_item_information(item),
        })

    @staticmethod
    def my_post(request, data, item_id):
        item = Item.objects.get(pk=item_id)
        if data.get('name') is not None:
            item.name = data['name']
        # 网页端用 user_id 来选择author
        if data.get('item.author_id') is not None:
            item.author = User.objects.get(pk=data['item.author_id'])
        if data.get('item.author') is not None:
            item.author = User.objects.get(username=data['item.author'])
        if data.get('item.pos_x') is not None:
            item.pos_x = data['item.pos_x']
        if data.get('item.pos_y') is not None:
            item.pos_y = data['item.pos_y']
        if data.get('item.pos_z') is not None:
            item.pos_z = data['item.pos_z']
        if data.get('item.rot_x') is not None:
            item.rot_x = data['item.rot_x']
        if data.get('item.rot_y') is not None:
            item.rot_y = data['item.rot_y']
        if data.get('item.rot_z') is not None:
            item.rot_z = data['item.rot_z']
        if data.get('item.row_w') is not None:
            item.row_w = data['item.rot_w']
        if data.get('item.scl_x') is not None:
            item.scl_x = data['item.scl_x']
        if data.get('item.scl_y') is not None:
            item.scl_y = data['item.scl_y']
        if data.get('item.scl_z') is not None:
            item.scl_z = data['item.scl_z']
        item.save()
        return get_success_response()


def get_item_information(item):
    result_dict = {
        'id': item.pk,
        'name': item.name,
        'pos_x': item.pos_x,
        'pos_y': item.pos_y,
        'pos_z': item.pos_z,
        'rot_x': item.rot_x,
        'rot_y': item.rot_y,
        'rot_z': item.rot_z,
        'rot_w': item.rot_w,
        'scl_x': item.scl_x,
        'scl_y': item.scl_y,
        'scl_z': item.scl_z,
    }
    # 解决可能没有author的bug
    author = None
    author_id = None
    if item.author:
        author = item.author.username
        author_id = item.author.pk
    if author is not None:
        result_dict['author'] = author
    if author_id is not None:
        result_dict['author_id'] = author_id
    if item.file is not None:
        result_dict['file'] = item.file.name
    return result_dict


class APIAddItem(APIView):
    class MyForm(Form):
        name = CharField(label='name')
        author_id = IntegerField(label='author_id')

    @staticmethod
    def my_post(request, cleaned_data, scene_id):
        scene = Scene.objects.get(pk=scene_id)
        group = scene.group
        user = User.objects.get(pk=cleaned_data['author_id'])
        item = Item.objects.create(
            name=cleaned_data['name'],
            scene=scene,
            author=user
        )
        # 分配物体的object权限到组里
        assign_perm('gallery.view_item', group, item)
        assign_perm('gallery.change_item', group, item)
        assign_perm('gallery.delete_item', group, item)
        # 分配物体的object权限给用户
        assign_perm('gallery.view_item', user, item)
        assign_perm('gallery.change_item', user, item)
        assign_perm('gallery.delete_item', user, item)
        item.save()
        return get_success_response()


class APIDeleteItem(APIView):
    
    @staticmethod
    def my_del(request, item_id):
        item = Item.objects.get(pk=item_id)
        # 删除权限
        # todo
        item.delete()
        return get_success_response()


@method_decorator(csrf_exempt, 'dispatch')
class APIItemFile(View):

    @staticmethod
    def get(request, item_id):
        item = Item.objects.get(pk=item_id)
        f_p = os.path.join(MEDIA_ROOT, item.file.name)
        f = open(f_p, 'rb')
        return FileResponse(f)

    @staticmethod
    def post(request, item_id):
        # todo: 代码复用
        file = request.FILES.get('file')
        data = request.POST.get('data')
        item = Item.objects.get(pk=item_id)
        item.file = file
        item.save()
        return JsonResponse({
            "item": get_item_information(item)
        })



class APIGetArtistList(APIView):

    @staticmethod
    def my_get(request):
        artist_list = []
        for user in User.objects.all():
            # 判断方式:用户不在任何组里即为artist
            # 以后再改 Artist全部丢到一个组里,现在就先这样判
            if not len(user.groups.all()) and not user.is_superuser and user.is_active and not user.username == 'AnonymousUser' and not user.has_perm('gallery.change_scene'):
                artist_list.append({
                    'username': user.username,
                    'id': user.pk,
                })
        return JsonResponse({
            'artist_list': artist_list,
        })
