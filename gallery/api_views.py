import json
from django.views import View
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.forms import Form, CharField
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required

MAX_CHAR_LENGTH = 32


@method_decorator(csrf_exempt, 'dispatch')
class APILoginView(View):
    def post(self, request):
        class APILoginPostForm(Form):
            username = CharField()
            password = CharField()
        try:
            data = json.loads(request.body)
        except Exception as e:
            return JsonResponse({
                'error_type': type(e),
                'error_message': str(e),
            }, status=400)
        form = APILoginPostForm(data)
        if not form.is_valid():
            return JsonResponse({
                'error_type', 'form_valid_failed',
                'error_message', form.errors,
            }, status=400)
        cleaned_data = form.clean()
        user = authenticate(
            username=cleaned_data['username'],
            password=cleaned_data['password']
        )
        if user is None:
            return JsonResponse({
                'error_type': 'login_failed',
                'error_message': 'User Authenticate Failed',
            }, status=403)
        logout(request)
        login(request, user)
        return JsonResponse({

        }, status=200)
