import random
import hashlib
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
    NotFoundError,
)
from .models import Scene, Item, Exhibition, Tool
from guardian.shortcuts import assign_perm, get_perms
from guardian.decorators import permission_required, permission_required_or_403
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
            print('Unexcepted Error: %s: %s' % (str(type(e)), str(e)))
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
            print('Catch Error %s: %s' % (str(type(e)), str(e)))
            return JsonResponse({
                'error_type': str(e.__class__.__name__),  # 使用类名作为错误类型
                'error_message': str(e)  # 调用e的__str__()方法，获取错误详细解释
            }, status=e.status)
        # 捕获未定义的错误
        except Exception as e:
            # 输出错误类型和错误信息到控制台
            print('Unexcepted Error %s: %s' % (str(type(e)), str(e)))
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
    def my_get(request):
        if request.user.is_authenticated:
            return JsonResponse({
                'user_type': get_user_type(request.user),
            })
        else:
            raise AuthenticateError

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
            'user_type': get_user_type(request.user),
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
        scene_id = IntegerField(label='scene_id', required=False)
        exhibition_id = IntegerField(label='exhibition_id', required=False)

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
            # 普通用户
            artist_group = Group.objects.get_or_create(name='artist_group')[0]
            artist_group.user_set.add(user)
        elif user_type == 'teacher':
            # 添加老师到teacher_group组
            teacher_group = Group.objects.get_or_create(name='teacher_group')[0]
            teacher_group.user_set.add(user)
            # 老师teacher属于scene.group组，该组拥有scene内所有item的object权限，和对应scene的object权限
            scene_id = cleaned_data['scene_id']
            scene = Scene.objects.get(pk=scene_id)
            group = scene.group
            group.user_set.add(user)
        elif user_type == 'stuff':
            # 添加stuff到stuff_group组
            stuff_group = Group.objects.get_or_create(name='stuff_group')[0]
            stuff_group.user_set.add(user)
            # 策展管理员stuff拥有所属exhibition下所有scene的object权限
            exhibition_id = cleaned_data['exhibition_id']
            exhibition = Exhibition.objects.get(pk=exhibition_id)
            group = exhibition.group
            group.user_set.add(user)

        elif user_type == 'superuser':
            # 添加超级用户到超级用户组
            superuser_group = Group.objects.get_or_create(name='superuser_group')[0]
            superuser_group.user_set.add(user)
            user.is_superuser = True
        else:
            # 用户提交了未定义的类型，引发一个错误
            raise FormValidError(message="Unknown user type, can not signup")

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
                'user_type': get_user_type(user),
            })
        return JsonResponse(user_list, safe=False)


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
        user_type = get_user_type(request.user)
        return JsonResponse({
            'user_type': user_type,
        })


# 获取用户类型
def get_user_type(user):
    user_type = ''
    # 游客
    if not user.is_authenticated:
        user_type = 'anonymous'
    if user.is_superuser:
        user_type = 'superuser'
    for group in user.groups.all():
        group_name = group.name
        if group_name == 'artist_group':
            user_type = 'artist'
            break
        elif group_name == 'teacher_group':
            user_type = 'teacher'
            break
        elif group_name == 'stuff_group':
            user_type = 'stuff'
            break
        elif group_name == 'superuser_group':
            user_type = 'superuser'
    if not user_type:
        raise Error("User type not define", status=500)
    return user_type

# 用于注册的scenelist
class APIGetSignupSceneList(APIView):

    @staticmethod
    def my_get(request):
        user_type = get_user_type(request.user)
        scene_list = []
        for scene in Scene.objects.all():
            scene_list.append(get_scene_information(scene))

        return JsonResponse(scene_list, safe=False)


# 不限定exhibition，获取所有scene
class APIGetAllSceneList(APIView):

    @staticmethod
    def my_get(request):
        user_type = get_user_type(request.user)
        scene_list = []
        # 拒绝普通用户
        if user_type == 'artist':
            raise NoPermission
        for scene in Scene.objects.all():
            if check_perm('gallery.change_scene', request, scene):
                scene_list.append(scene)
        return JsonResponse(scene_list, safe=False)


# 进行权限检查的scene list版本
class APIGetSceneList(APIView):

    @staticmethod
    def my_get(request, exhibition_id):
        user_type = get_user_type(request.user)
        scene_list = []
        # 拒绝普通用户
        if user_type == 'artist':
            raise NoPermission
        exhibition = Exhibition.objects.get(pk=exhibition_id)
        for scene in Scene.objects.filter(exhibition=exhibition):
            if check_perm('gallery.change_scene', request, scene):
                scene_list.append(get_scene_information(scene))
        return JsonResponse(scene_list, safe=False)


def get_scene_information(scene):
    return {
        'id': scene.pk,
        'name': scene.name,
        'file': scene.file.name,
    }


class APIAddNewScene(APIView):
    class MyForm(Form):
        name = CharField(label='name')
        exhibition_id = IntegerField(label='exhibition_id')

    @staticmethod
    def my_post(request, cleaned_data):
        name = cleaned_data['name']
        exhibition_id = cleaned_data['exhibition_id']

        exhibition = Exhibition.objects.get(pk=exhibition_id)
        exhibition_group = exhibition.group

        # 检查 name 是否已经存在
        if len(Scene.objects.filter(name=name)) > 0:
            raise Error(message='Scene name has been taken', status=403)
        if len(Group.objects.filter(name=name)) > 0:
            raise Error(message='Scene permission group name has been taken.', status=403)

        group = Group.objects.create(name=gen_random_name(name))
        scene = Scene.objects.create(name=name, group=group, exhibition=exhibition)

        # 分配这个展厅的object权限到组里
        assign_perm('gallery.view_scene', group, scene)
        assign_perm('gallery.change_scene', group, scene)
        # assign_perm('gallery.add_scene', group, scene)
        # assign_perm('gallery.delete_scene', group, scene)

        # 添加该展厅的object权限到对应exhibition里
        assign_perm('gallery.view_scene', exhibition_group, scene)
        assign_perm('gallery.change_scene', exhibition_group, scene)
        # assign_perm('gallery.add_scene', exhibition_group, scene)
        assign_perm('gallery.delete_scene', exhibition_group, scene)

        group.save()

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

    def get(self, request, *args, **kwargs):
        try: 
            return self.my_get(request, *args, **kwargs)
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

    @staticmethod
    def my_get(request, scene_id):
        scene = Scene.objects.get(pk=scene_id)
        f_p = os.path.join(MEDIA_ROOT, scene.file.name)
        if not os.path.exists(f_p):
            raise NotFoundError
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
            item_list.append(get_item_information(item))
        return JsonResponse(item_list, safe=False)


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

# todo args include user and check perms
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
        artist_group = Group.objects.get_or_create(name='artist_group')[0]
        for user in artist_group.user_set.all():
            artist_list.append({
                'username': user.username,
                'id': user.pk,
            })
        return JsonResponse({
            'artist_list': artist_list,
        })


def gen_random_name(data):
    sha1 = hashlib.sha1()
    sha1.update(str(random.random()).encode())
    random_string = sha1.hexdigest()
    return '_'.join([data, random_string])

class APIExhibitionAdd(APIView):
    class MyForm(Form):
        name = CharField(label='name')

    @staticmethod
    def my_post(request, cleaned_data):
        # 只有superuser才能新建exhibition
        if not request.user.is_superuser:
            raise NoPermission
        exhibition_name = cleaned_data['name']
        exhibition = Exhibition.objects.create(name=exhibition_name)

        group = Group.objects.create(name=gen_random_name(exhibition_name))
        exhibition.group = group

        # 分配操作该exhibition的object权限到组里
        assign_perm('gallery.view_exhibition', group, exhibition)
        assign_perm('gallery.change_exhibition', group, exhibition)

        group.save()
        exhibition.save()
        return get_success_response()


class APIExhibitionInfo(APIView):
    class MyForm(Form):
        name = CharField(label='name')

    @staticmethod
    def my_get(request, exhibition_id):
        exhibition = Exhibition.objects.get(pk=exhibition_id)
        return {
            'exhibition': get_exhibition_information(request, exhibition)
        }
    
    @staticmethod
    @permission_required_or_403(
        'gallery.change_exhibition',
        (Exhibition, 'pk', 'exhibition_id'),
        accept_global_perms=True
    )
    def my_post(request, cleaned_data, exhibition_id):
        exhibition = Exhibition.objects.get(pk=exhibition_id)
        name = cleaned_data['name']
        exhibition.name = name
        exhibition.save()
        return get_success_response()


class APIExhibitionDelete(APIView):

    @staticmethod
    def my_del(request, exhibition_id):
        exhibition = Exhibition.objects.get(pk=exhibition_id)
        exhibition.delete()
        return get_success_response()


# 不不进行权限检查的exhibition 版本
class APISignupExhibitionList(APIView):

    @staticmethod
    def my_get(request):
        exhibition_list = []
        for exhibition in Exhibition.objects.all():
            exhibition_list.append(get_exhibition_information(exhibition))
        return JsonResponse(exhibition_list, safe=False)


# 进行权限检查的exhibition list 版本
class APIExhibitionList(APIView):

    @staticmethod
    def my_get(request):
        exhibition_list = []
        for exhibition in Exhibition.objects.all():
            if check_perm('gallery.change_exhibition', request, exhibition):
                exhibition_list.append(get_exhibition_information(exhibition))
        return JsonResponse(exhibition_list, safe=False)

def get_exhibition_information(exhibition):
    return {
        'id': exhibition.pk,
        'name': exhibition.name,
    }


# check object permission and global permission
def check_perm(perm_string, request, obj):
    if request.user.is_superuser:
        return True
    if request.user.has_perm(perm_string) or request.user.has_perm(perm_string, obj):
        return True
    else:
        return False


# get tool list
class APIGetToolList(APIView):

    @staticmethod
    def my_get(request, scene_id):
        scene = Scene.objects.get(pk=scene_id)
        tool_list = []
        for tool in Tool.objects.filter(scene=scene):
            tool_list.append({
                'name': tool.name,
            })
        return JsonResponse(tool_list, safe=False)

