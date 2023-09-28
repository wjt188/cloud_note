import hashlib

from django.shortcuts import render
from django.http import HttpResponse,HttpResponseRedirect
from .models import User
from .modules import generate_hash

# Create your views here.

def reg_view(request):
    if request.method == 'GET':
        return render(request,'user/register.html')
    elif request.method == 'POST':
        #获取表单提交数据
        username = request.POST['username']
        password_1 = request.POST['password_1']
        password_2 = request.POST['password_2']
        #校验密码是否一致
        if password_1 != password_2:
            return HttpResponse('两次密码输入不一致')
        old_users = User.objects.filter(username=username)
        if old_users:
            return HttpResponse('该用户已注册')
        #密码加密
        hash_password = generate_hash(password_1)
        #插入数据
        try:
            user = User.objects.create(username=username,password=hash_password)
        except Exception as e:
            print("--create user is %s" % (e))
            return HttpResponse("用户已注册")
        #免登录一天
        request.session['username'] = username
        request.session['uid'] = user.id
        #修改session的存储时间

        return HttpResponseRedirect('/index')


def login_view(request):
    if request.method == 'GET':
        # 检查登录状态，若登录，显示已登录
        if request.session.get('username') and request.session.get('uid'):
            return HttpResponse('--已登录--')
        # 检查cookie
        c_username= request.COOKIES.get('username')
        c_uid = request.COOKIES.get('uid')
        if c_username and c_uid:
            # 回写session
            request.session['username'] = c_username
            request.session['uid'] = c_uid
            return HttpResponse('--已登录--')
        return render(request,'user/login.html')
    elif request.method == 'POST':
        # 获取表单提交数据
        username = request.POST['username']
        password = request.POST['password']

        try:
            user = User.objects.get(username=username)
        except Exception as e:
            print('--login user error %s' % (e))
            return HttpResponse('用户名或密码错误')

        # 比对密码
        m = hashlib.md5()
        m.update(password.encode())

        if m.hexdigest() != user.password:
            return HttpResponse('用户名或密码错误')

        # 记录会话状态
        request.session['username'] = username
        request.session['uid'] = user.id

        resp = HttpResponseRedirect('/index')
        # 判断用户是否点击 "记住用户名"
        # 点击选了，Cookies存储usernmae，uid，时间为3天
        if 'remember' in request.POST:
            resp.set_cookie('username', username, 3600*24*3)
            resp.set_cookie('uid', user.id, 3600*24*3)

        return resp