# 自定义错误类


# 自定义基类异常
class Error(Exception):
    def __init__(self, message, status):
        super().__init__(message, status)
        self.message = message  # 错误信息
        self.status = status  # Http状态码

    def __str__(self):
        return self.message


class NoPermission(Error):
    def __init__(self, message='No Permission', status=403):
        super().__init__(message, status)


# 未定义API表单
class APIFormNotDefine(Error):
    def __init__(self, message='API form not define', status=500):
        super().__init__(message, status)


# Json 解码错误就抛出这个异常
class JsonError(Error):
    def __init__(self, message='Json decode error', status=400):
        super().__init__(message, status)


# 表单Valid异常
class FormValidError(Error):
    def __init__(self, message='Form Valid Error', status=500):
        super().__init__(message, status)


# 用户认证失败
class AuthenticateError(Error):
    def __init__(self, message='User Authenticate Failed', status=401):
        super().__init__(message, status)


# 瞎jb测试用代码
if __name__ == '__main__':
    try:
        raise AuthenticateError('blablabla')
    # 用基类Error可以捕获所有自定义异常
    except Error as e:
        print(type(e))
        print(str(e))
        print(e.__class__.__name__)
