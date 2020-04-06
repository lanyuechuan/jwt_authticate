from rest_framework.response import Response
from rest_framework.views import APIView
from DWTDemo import settings
from app01 import models
import uuid

# 传统的token认证方式
class LoginView(APIView):
    """用户登录"""
    def post(self,request,*args,**kwargs):
        user = request.data.get("username")
        pwd = request.data.get("password")
        user_obj = models.UserInfo.objects.filter(username=user,password=pwd).first()
        if not user_obj:
            return Response({"code":1000,"error":"用户名或密码错误"})
        # 生成一个随机字符串，即token
        random_str = str(uuid.uuid4())
        user_obj.token = random_str
        user_obj.save()
        return Response({"code": 1001, "data": random_str})


class OrderView(APIView):
    def get(self,request,*args,**kwargs):
        token = request.query_params.get("token")
        if not token:
            return Response({"code":2000,"error":"登录成功之后才能访问"})
        if not models.UserInfo.objects.filter(token=token).first():
            return Response({"code": 2001, "error": "token无效"})
        return Response("订单列表")

# jwt认证方式
class JwtLoginView(APIView):
    """用户登录"""
    def post(self,request,*args,**kwargs):
        user = request.data.get("username")
        pwd = request.data.get("password")
        user_obj = models.UserInfo.objects.filter(username=user,password=pwd).first()
        if not user_obj:
            return Response({"code":1000,"error":"用户名或密码错误"})

        import jwt
        import datetime
        SALT = settings.SECRET_KEY

        # 构造header
        headers = {
            'typ': 'jwt',
            'alg': 'HS256'
        }
        # 构造payload
        payload = {
            'id': user_obj.id,  # 自定义用户ID
            'username': user_obj.username,  # 自定义用户名
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=1)  # 超时时间(当前时间加了1分钟，即1分钟后过期)
        }
        token = jwt.encode(payload=payload, key=SALT, algorithm="HS256", headers=headers).decode('utf-8')
        return Response({"code": 1001, "data": token})


class JwtOrderView(APIView):
    def get(self,request,*args,**kwargs):
        # 获取token并判断token得合法性
        token = request.query_params.get("token")

        # 1、切割
        # 2、解密第二段/判断是否过期
        # 3、验证第三段的合法性
        import jwt
        from jwt import exceptions

        SALT = settings.SECRET_KEY
        payload = None
        message = None
        try:
            # 看到了那个True了吗，但凡payload有返回值，就表示校验成功
            payload = jwt.decode(token, SALT, True)
        except exceptions.ExpiredSignatureError:
            message = 'token已失效'
        except jwt.DecodeError:
            message = 'token认证失败'
        except jwt.InvalidTokenError:
            message = '非法的token'
        if not payload:
            return Response({"code":1003,"error":message})


        print(payload["id"],payload["username"])
        return Response("订单列表")


# 公司里要这样用
from app01.extensions.auth import JwtQueryParamsAuthentication
from app01.utils.jwt_auth import create_token

class ProLoginView(APIView):
    """用户登录"""
    authentication_classes = []  # 先看自己类中的认证类，我没有就不验证
    def post(self,request,*args,**kwargs):
        user = request.data.get("username")
        pwd = request.data.get("password")
        user_obj = models.UserInfo.objects.filter(username=user,password=pwd).first()
        if not user_obj:
            return Response({"code":1000,"error":"用户名或密码错误"})

        token = create_token({"id":user_obj.id,"name":user_obj.username})
        return Response({"code": 1001, "data": token})


class ProOrderView(APIView):
    # 有点像django中间件，把认证动作写在这些个类中,我直接加到setting里边，drf是默认先验证的，所以相当于我的所有接口都加上了验证功能，但是有些接口不需要登录，就比如登录页面
    # authentication_classes = [JwtQueryParamsAuthentication,]
    def get(self,request,*args,**kwargs):
        print(request.user)
        return Response("订单列表")