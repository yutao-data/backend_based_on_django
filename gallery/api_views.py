import random
import hashlib
import json
import os.path
import copy
from backend_based_on_django.settings import MEDIA_ROOT
from django.views import View
from django.http import JsonResponse, FileResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.forms import (
    Form,
    CharField,
    IntegerField,
    NullBooleanField,
    FileField,
    FloatField,
    MultipleChoiceField,
    JSONField,
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
    NoScene,
)
from .models import (
    Scene, 
    Item, 
    Exhibition, 
    Tool,
    SignupRequest,
)
from guardian.shortcuts import assign_perm, get_perms
from guardian.decorators import permission_required, permission_required_or_403
from django.contrib.auth.decorators import login_required

MAX_CHAR_LENGTH = 32


# 返回一个状态码200没啥内容的Json用于表示成功
def get_success_response(message='Success'):
    return JsonResponse({
        'message': message
    }, status=200)

def gen_random_name(data):
    sha1 = hashlib.sha1()
    sha1.update(str(random.random()).encode())
    random_string = sha1.hexdigest()
    return '_'.join([data, random_string])

# check object permission and global permission
def check_perm(perm_string, request, obj):
    if request.user.is_superuser:
        return True
    if request.user.has_perm(perm_string) or request.user.has_perm(perm_string, obj):
        return True
    else:
        return False

def get_signup_request_information(signup_request):
    exhibition_name = None
    if signup_request.exhibition:
        exhibition_name = signup_request.exhibition.name
    return {
        'id': signup_request.pk,
        'username': signup_request.user.username,
        'user_type': signup_request.user_type,
        'exhibition': exhibition_name,
    }

def get_exhibition_information(exhibition):
    scene_name = ''
    scene_id = None
    if exhibition.scene:
        scene_name = exhibition.scene.name
        scene_id = exhibition.scene.pk
    return {
        'id': exhibition.pk,
        'name': exhibition.name,
        'scene': scene_name,
        'scene_id': scene_id,
    }

def get_exhibition_users_list(exhibition):
    user_list = []
    for user in exhibition.users.user_set.all():
        user_information = get_user_information(user)
        user_information['user_type'] = get_user_type(user, exhibition)
        user_list.append(user_information)
    return user_list

def get_scene_information(scene):
    author_name = ''
    author_id = None
    if scene.author:
        author_name = scene.author.username
        author_id = scene.author.pk
    return {
        'id': scene.pk,
        'name': scene.name,
        'author': author_name,
        'author_id': author_id,
        'file': scene.file.name,
    }

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
        'description': item.description,
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

def get_tool_information(tool):
    return {
        'name': tool.name,
        'angle': tool.angle,
    }

# 获取用户详细信息
def get_user_information(user):
    return {
        'id': user.pk,
        'username': user.username,
        'is_active': user.is_active,
        'is_superuser': user.is_superuser,
    }

# 获取或创建manager_group，并分配权限
def get_manager_group():
    manager_group, created = Group.objects.get_or_create(name="manager_group")
    # 初次创建：配置权限
    if created:
        assign_perm('gallery.add_scene', manager_group)
    return manager_group

# 获取用户类型
# 未登录 '' 空字符串
# 用户不在该组内 '' 空字符串
def get_user_type(user, exhibition):
    user_type = ''

    # 如果传入exhibition是None，则只检查是否为superuser
    if exhibition is None:
        if user.is_superuser:
            return 'superuser'
        else:
            return ''

    if user in exhibition.admins.user_set.all():
        user_type = 'admin'
    elif user in exhibition.managers.user_set.all():
        user_type = 'manager'
    elif user in exhibition.stuffs.user_set.all():
        user_type = 'stuff'
    elif user in exhibition.artists.user_set.all():
        user_type = 'artist'
    else:
        user_type = ''

    if user.is_superuser:
        user_type = 'superuser'

    return user_type


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
        data = None
        cleaned_data = None
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
            # debug: cleaned_data
            print('cleaned_data: ', str(cleaned_data))
            # 调用真实的my_post函数处理请求
            return self.my_post(requests, cleaned_data, *args, **kwargs)

        # 统一的错误处理，减少代码重复
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
            print('request.body: ', str(requests.body))
            print('json data: ', str(data))
            print('cleaned_data: ', str(cleaned_data))
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
            return get_success_response()
        else:
            raise AuthenticateError

    @staticmethod
    def my_post(request, cleaned_data):
        user = authenticate(
            username=cleaned_data['username'],
            password=cleaned_data['password'],
        )
        if user is None:
            raise AuthenticateError
        logout(request)
        login(request, user)
        return get_success_response()


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
        # 可选值：用户申请的权限列表
        # 格式：[
        #    {"user_type": "artist", "exhibition_id": 123},
        #    {"user_type": "manager", "exhibition_id": 113},
        #    {"user_type": "admin", "exhibition_id": 111},
        #    {"user_type": "superuser"}
        #]
        permission_list = JSONField(label='permission_list', required=False)

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

        user.save()
    
        
        if cleaned_data['permission_list']:
            permission_list = cleaned_data['permission_list']
            for permission in permission_list:

                # 用户类型有: artist/stuff/manager/admin/superuser
                # 分别对应展品上传者/策展团队成员/展览负责人/展览负责人（可添加其他用户作为展览负责人）/站点管理员（超级用户user.is_superuser=true）

                user_type = permission['user_type']
                if not user_type in ['artist', 'stuff', 'manager', 'admin', 'superuser']:
                    raise FormValidError("Not allow user_type " + user_type)
                
                exhibition = None
                # superuser类型的用户注册不需要exhibition_id
                if user_type and not user_type == 'superuser':
                    exhibition_id = permission['exhibition_id']
                    exhibition = Exhibition.objects.get(pk=exhibition_id)

                # manager_group 用来储存所有具有manager或admin权限的用户
                # 用于添加scene时，不提供exhibition_id的权限检查
                if user_type in ['manager', 'admin']:
                    manager_group = get_manager_group()
                    manager_group.user_set.add(user)

                # 创建用户注册请求
                signup_request = SignupRequest.objects.create(
                    user = user,
                    user_type = user_type,
                    exhibition = exhibition,
                )
                signup_request.save()
        else:
            # 创建不带任何exhibition的用户注册请求
            signup_request = SignupRequest.objects.create(
                user = user,
                user_type = '',
                exhibition = None,
            )
            signup_request.save()


        return get_success_response()


class APIAllSignupRequestListView(APIView):

    @staticmethod
    def my_get(request):
        signup_request_list = []
        for signup_request in SignupRequest.objects.all():
            signup_request_list.append(get_signup_request_information(signup_request))
        return JsonResponse(signup_request_list, safe=False)


class APISignupRequestListView(APIView):

    @staticmethod
    def my_get(request, exhibition_id):
        signup_request_list = []
        exhibition = Exhibition.objects.get(pk=exhibition_id)
        for signup_request in SignupRequest.objects.filter(exhibition=exhibition):
            signup_request_list.append(get_signup_request_information(signup_request))
        return JsonResponse(signup_request_list, safe=False)


class APISignupRequestView(APIView):

    class MyForm(Form):
        accept = NullBooleanField(label='accept')

    @staticmethod
    def my_post(request, cleaned_data, signuprequest_id):
        accept = cleaned_data['accept']
        signup_request = SignupRequest.objects.get(pk=signuprequest_id)
        user = signup_request.user
        if accept:
            # 如果这个注册请求有指定exhibition，则配置相应权限
            if signup_request.exhibition:
                exhibition = signup_request.exhibition
                user_type = signup_request.user_type
                if user_type == 'artist':
                    exhibition.artists.user_set.add(user)
                elif user_type == 'stuff':
                    exhibition.stuffs.user_set.add(user)
                elif user_type == 'manager':
                    exhibition.managers.user_set.add(user)
                elif user_type == 'admin':
                    exhibition.admins.user_set.add(user)
                else:
                    raise Error("Not support user_type "+user_type, 500)
                # 将用户加入对应exhibition的users组，方便以后查询
                exhibition.users.user_set.add(user)
            if signup_request.user_type == 'superuser':
                user.is_superuser = True
            # 只要同意了任意注册请求即激活用户
            user.is_active = True
            user.save()
        # 不管是否同意注册请求，处理完之后都删掉该请求
        signup_request.delete()
        # 检查该用户是否未被激活并已被拒绝掉所有请求
        print(user.is_active)
        print(SignupRequest.objects.filter(user=user))
        if not user.is_active and not SignupRequest.objects.filter(user=user):
            user.delete()

        return get_success_response()


class APIUserDeleteView(APIView):
    class MyForm(Form):
        id = IntegerField(label='id')

    @staticmethod
    def my_del(request, user_id):
        user = User.objects.get(pk=user_id)
        user.delete()
        return get_success_response()


class APIAllUserList(APIView):

    @staticmethod
    def my_get(request):
        user_list = []
        for user in User.objects.all():
            user_list.append(get_user_information(user))
        return JsonResponse(user_list, safe=False)


# 查询用户的全局信息
# 和APIExhibitionUserView的区别在于
# 本GET方法返回的user_type字段仅有'superuser'和空字符串两种可能值
# APIExhibitionUserView返回artist/stuff/manage/teacher或空字符串
class APIUserView(APIView):

    @staticmethod
    def my_get(request, user_id):
        user = User.objects.get(pk=user_id)
        user_information = get_user_information(user)
        user_information['user_type'] = get_user_type(user, None)
        return JsonResponse({
            'user': user_information,
        })


# 获取限定exhibition内的用户信息
class APIExhibitionUserView(APIView):
    
    @staticmethod
    def my_get(request, exhibition_id, user_id):
        user = User.objects.get(pk=user_id)
        exhibition = Exhibition.objects.get(pk=exhibition_id)
        user_information = get_user_information(user)
        user_information['user_type'] = get_user_type(user, exhibition)
        return JsonResponse({
            'user': user_information,
        })


# 获取所有scene
class APISceneList(APIView):

    @staticmethod
    def my_get(request):
        scene_list = []
        for scene in Scene.objects.all():
            scene_list.append(get_scene_information(scene))
        return JsonResponse(scene_list, safe=False)


class APISceneAdd(APIView):
    class MyForm(Form):
        name = CharField(label='name')
        author_id = IntegerField(label='author_id', required=False)
        author = CharField(label='author', required=False)

    @staticmethod
    def my_post(request, cleaned_data):
        if not request.user.has_perm('gallery.add_scene'):
            raise NoPermission
        name = cleaned_data['name']

        # 检查 name 是否已经存在
        if len(Scene.objects.filter(name=name)) > 0:
            raise Error(message='Scene name has been taken', status=403)
        if len(Group.objects.filter(name=name)) > 0:
            raise Error(message='Scene permission group name has been taken.', status=403)

        author = None
        # 如果传入了author
        if cleaned_data['author']:
            author = User.objects.get(username=cleaned_data['author'])

        # 如果有传入author_id
        if not cleaned_data['author_id'] is None:
            author = User.objects.get(pk=cleaned_data['author_id'])

        scene = Scene.objects.create(
            name=name,
            author=author,
        )

        scene.save()

        return JsonResponse({
            "scene": get_scene_information(scene)
        })


# 获取单个Scene的详细信息
class APISceneInformation(APIView):

    @staticmethod
    def my_get(request, scene_id):
        scene = Scene.objects.get(pk=scene_id)
        return JsonResponse({
            'scene': get_scene_information(scene)
        })

    class MyForm(Form):
        name = CharField(label='name', required=False)
        author_id = IntegerField(label='author_id', required=False)
        author = CharField(label='author', required=False)

    @staticmethod
    @permission_required_or_403(
        'gallery.change_scene',
        (Scene, 'pk', 'scene_id'),
        accept_global_perms=True
    )
    def my_post(request, cleaned_data, scene_id):
        scene = Scene.objects.get(pk=scene_id)

        if cleaned_data['name']:
            scene.name = cleaned_data['name']
        if cleaned_data['author']:
            author = User.objects.get(username=cleaned_data['author'])
            scene.author = author
        if not cleaned_data['author_id'] is None:
            author = User.objects.get(pk=cleaned_data['author_id'])
            scene.author = author

        scene.save()

        return get_success_response()


@method_decorator(csrf_exempt, 'dispatch')
class APISceneFile(View):

    @staticmethod
    def post(request, scene_id):
        file = request.FILES.get('file')
        print("file len: ", str(len(file)))
        filename = request.POST.get('filename')
        scene = Scene.objects.get(pk=scene_id)
        file.name = filename
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
        scene.delete()
        return get_success_response()


class APIGetItemList(APIView):

    @staticmethod
    def my_get(request, exhibition_id):
        exhibition = Exhibition.objects.get(pk=exhibition_id)
        if not exhibition.scene:
            raise NoScene
        item_list = []
        scene = exhibition.scene
        for item in Item.objects.filter(scene=scene):
            item_list.append(get_item_information(item))
        return JsonResponse(item_list, safe=False)


class APIItemInformation(APIView):
    use_form = False

    @staticmethod
    def my_get(request, exhibition_id, item_id):
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
        if data.get('author_id') is not None:
            item.author = User.objects.get(pk=data['author_id'])
        if data.get('author') is not None:
            item.author = User.objects.get(username=data['author'])
        if data.get('pos_x') is not None:
            item.pos_x = data['pos_x']
        if data.get('pos_y') is not None:
            item.pos_y = data['pos_y']
        if data.get('pos_z') is not None:
            item.pos_z = data['pos_z']
        if data.get('rot_x') is not None:
            item.rot_x = data['rot_x']
        if data.get('rot_y') is not None:
            item.rot_y = data['rot_y']
        if data.get('rot_z') is not None:
            item.rot_z = data['rot_z']
        if data.get('row_w') is not None:
            item.row_w = data['rot_w']
        if data.get('scl_x') is not None:
            item.scl_x = data['scl_x']
        if data.get('scl_y') is not None:
            item.scl_y = data['scl_y']
        if data.get('scl_z') is not None:
            item.scl_z = data['scl_z']
        if data.get('description') is not None:
            item.description = data['description']
        item.save()
        return get_success_response()


class APIItemAdd(APIView):
    class MyForm(Form):
        name = CharField(label='name')
        author = CharField(label='author', required=False)
        author_id = IntegerField(label='author_id', required=False)
        stuff = CharField(label='stuff', required=False)
        stuff_id = IntegerField(label='stuff_id', required=False)
        pos_x = FloatField(label='pos_x', required=False)
        pos_y = FloatField(label='pos_y', required=False)
        pos_z = FloatField(label='pos_z', required=False)
        rot_x = FloatField(label='rot_x', required=False)
        rot_y = FloatField(label='rot_y', required=False)
        rot_z = FloatField(label='rot_z', required=False)
        rot_w = FloatField(label='rot_w', required=False)
        scl_x = FloatField(label='scl_x', required=False)
        scl_y = FloatField(label='scl_y', required=False)
        scl_z = FloatField(label='scl_z', required=False)
        description = CharField(label='description', required=False)

    @staticmethod
    def my_post(request, cleaned_data, exhibition_id):
        # check author and author_id is missing
        if not cleaned_data['author'] and cleaned_data.get('author_id') is None:
            raise FormValidError(message='no author post')

        exhibition = Exhibition.objects.get(pk=exhibition_id)
        if not exhibition.scene:
            raise NoScene

        scene = exhibition.scene
        user = None
        if cleaned_data['author']:
            user = User.objects.get(username=cleaned_data['author'])
        if cleaned_data['author_id']:
            user = User.objects.get(pk=cleaned_data['author_id'])
        item = Item.objects.create(
            name=cleaned_data['name'],
            scene=scene,
            author=user
        )
        if cleaned_data.get('pos_x') is not None:
            item.pos_x = cleaned_data['pos_x']
        if cleaned_data.get('pos_y') is not None:
            item.pos_y = cleaned_data['pos_y']
        if cleaned_data.get('pos_z') is not None:
            item.pos_z = cleaned_data['pos_z']
        if cleaned_data.get('rot_x') is not None:
            item.rot_x = cleaned_data['rot_x']
        if cleaned_data.get('rot_y') is not None:
            item.rot_y = cleaned_data['rot_y']
        if cleaned_data.get('rot_z') is not None:
            item.rot_z = cleaned_data['rot_z']
        if cleaned_data.get('row_w') is not None:
            item.row_w = cleaned_data['rot_w']
        if cleaned_data.get('scl_x') is not None:
            item.scl_x = cleaned_data['scl_x']
        if cleaned_data.get('scl_y') is not None:
            item.scl_y = cleaned_data['scl_y']
        if cleaned_data.get('scl_z') is not None:
            item.scl_z = cleaned_data['scl_z']
        if cleaned_data.get('description') is not None:
            item.description = cleaned_data['description']
        item.save()
        # 前端要求只返回一个item id
        return HttpResponse(item.pk) 


class APIDeleteItem(APIView):
    
    @staticmethod
    def my_del(request, exhibition_id, item_id):
        item = Item.objects.get(pk=item_id)
        item.delete()
        return get_success_response()


@method_decorator(csrf_exempt, 'dispatch')
class APIItemFile(View):

    @staticmethod
    def get(request, exhibition_id, item_id):
        item = Item.objects.get(pk=item_id)
        f_p = os.path.join(MEDIA_ROOT, item.file.name)
        f = open(f_p, 'rb')
        return FileResponse(f)

    @staticmethod
    def post(request, item_id):
        # todo: 代码复用
        file = request.FILES.get('file')
        filename = request.POST.get('filename')
        item = Item.objects.get(pk=item_id)
        file.name = filename
        item.file = file
        item.save()
        return JsonResponse({
            "item": get_item_information(item)
        })


class APIExhibitionAdd(APIView):
    class MyForm(Form):
        name = CharField(label='name')
        scene_id = IntegerField(label='scene_id', required=False)

    @staticmethod
    def my_post(request, cleaned_data):
        exhibition_name = cleaned_data['name']
        exhibition = Exhibition.objects.create(name=exhibition_name)

        users = Group.objects.create(name=gen_random_name(exhibition_name+'_users'))
        artists = Group.objects.create(name=gen_random_name(exhibition_name+'_artists'))
        stuffs = Group.objects.create(name=gen_random_name(exhibition_name+'_stuffs'))
        managers = Group.objects.create(name=gen_random_name(exhibition_name+'_managers'))
        admins = Group.objects.create(name=gen_random_name(exhibition_name+'_admins'))

        # users 组包含exhibition内所有用户，方便查询
        # users 组不包含任何权限

        # 分配操作该exhibition的object权限到组里
        # artists组可以修改item
        # 但如果用户类型为artists需要额外检查item.author == request.user
        assign_perm('gallery.item_exhibition', artists, exhibition)
        # stuff组可以修改item和tool
        assign_perm('gallery.item_exhibition', stuffs, exhibition)
        assign_perm('gallery.tool_exhibition', stuffs, exhibition)
        # managers组可以修改item tool scene exhibition
        assign_perm('gallery.item_exhibition', managers, exhibition)
        assign_perm('gallery.tool_exhibition', managers, exhibition)
        assign_perm('gallery.scene_exhibition', managers, exhibition)
        assign_perm('gallery.change_exhibition', managers, exhibition)
        # admins组可以修改item tool scene exhibition
        # 相比managers多了一个可以添加其他用户作为管理员的权限
        assign_perm('gallery.item_exhibition', admins, exhibition)
        assign_perm('gallery.tool_exhibition', admins, exhibition)
        assign_perm('gallery.scene_exhibition', admins, exhibition)
        assign_perm('gallery.change_exhibition', admins, exhibition)
        assign_perm('gallery.admin_exhibition', admins, exhibition)

        exhibition.users = users
        exhibition.artists = artists
        exhibition.stuffs = stuffs
        exhibition.managers = managers
        exhibition.admins = admins

        users.save()
        artists.save()
        managers.save()
        admins.save()
        
        # 可选：设置exhibition的scene
        if cleaned_data.get('scene_id') is not None:
            scene = Scene.objects.get(pk=cleaned_data['scene_id'])
            exhibition.scene = scene

        exhibition.save()
        return JsonResponse(get_exhibition_information(exhibition))


class APIExhibitionInfo(APIView):
    class MyForm(Form):
        name = CharField(label='name', required=False)
        scene_id = IntegerField(label='scene_id', required=False)

    @staticmethod
    def my_get(request, exhibition_id):
        exhibition = Exhibition.objects.get(pk=exhibition_id)
        return JsonResponse({
            'exhibition': get_exhibition_information(exhibition),
            'user_list': get_exhibition_users_list(exhibition),
        })
    
    @staticmethod
    def my_post(request, cleaned_data, exhibition_id):
        exhibition = Exhibition.objects.get(pk=exhibition_id)
        if not cleaned_data.get('name') is None:
            exhibition.name = cleaned_data['name']
        if not cleaned_data.get('scene_id') is None:
            scene = Scene.objects.get(pk=cleaned_data['scene_id'])
            exhibition.scene = scene
        exhibition.save()
        return get_success_response()


class APIExhibitionDelete(APIView):

    @staticmethod
    def my_del(request, exhibition_id):
        exhibition = Exhibition.objects.get(pk=exhibition_id)
        exhibition.users.delete()
        exhibition.artists.delete()
        exhibition.stuffs.delete()
        exhibition.managers.delete()
        exhibition.admins.delete()
        exhibition.delete()
        return get_success_response()


class APIExhibitionList(APIView):

    @staticmethod
    def my_get(request):
        exhibition_list = []
        for exhibition in Exhibition.objects.all():
            exhibition_list.append(get_exhibition_information(exhibition))
        return JsonResponse(exhibition_list, safe=False)


# get tool list
class APIGetToolList(APIView):

    @staticmethod
    def my_get(request, exhibition_id):
        exhibition = Exhibition.objects.get(pk=exhibition_id)
        if not exhibition.scene:
            raise NoScene
        scene = exhibition.scene
        tool_list = []
        for tool in Tool.objects.filter(scene=scene):
            tool_list.append(get_tool_information(tool))
        return JsonResponse(tool_list, safe=False)


# add tool
class APIToolAdd(APIView):

    class MyForm(Form):
        name = CharField(label='name')
        angle = FloatField(label='angle', required=False)

    @staticmethod
    def my_post(request, cleaned_data, exhibition_id):
        exhibition = exhibition.objects.get(pk=exhibition_id)
        if not exhibition.scene:
            raise NoScene
        scene = exhibition.scene

        tool = Tool.objects.create(
            name=cleaned_data['name'],
            scene=scene,
            angle=cleaned_data['angle'],
        )

        tool.save()

        return JsonResponse(get_tool_information(tool))


class APIToolInfo(APIView):
    
    class MyForm(Form):
        name = CharField(label='name', required=False)
        angle = FloatField(label='angle', required=False)

    @staticmethod
    def my_post(request, cleaned_data, exhibition_id, tool_id):
        tool = Tool.objects.get(pk=tool_id)
        if cleaned_data['name']:
            tool.name = cleaned_data['name']
        if not cleaned_data['angle'] is None:
            tool.angle = cleaned_data['angle']
        return get_success_response()

    @staticmethod
    def my_get(request, exhibition_id, tool_id):
        tool = Tool.objects.get(pk=tool_id)
        return JsonResponse({
            'tool': get_tool_information(tool)
        })

class APIToolDelete(APIView):

    @staticmethod
    def my_del(request, exhibition_id, tool_id):
        tool = Tool.objects.get(pk=tool_id)
        tool.delete()
        return get_success_response()

    
