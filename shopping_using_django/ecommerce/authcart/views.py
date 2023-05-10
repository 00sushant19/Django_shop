from django.shortcuts import render,redirect,HttpResponse
from django.contrib.auth.models import User
from django.views.generic import View
from django.contrib import messages
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from .utils import TokenGenerator,generate_token
from django.utils.encoding import force_str,DjangoUnicodeDecodeError
from django.core.mail import EmailMessage
from django.conf import settings

from django.contrib.auth import authenticate,login,logout
# Create your views here.
def signup(request):
    if request.method=='POST':
        email=list(request.POST.getlist('email'))[0]
        password=request.POST['pass1']
        confirm_password=request.POST['pass2']
        print(email,password,confirm_password,list(request.POST.getlist('email')))
        if password!=confirm_password:
            messages.warning(request,"Password is Not Matching")
            return render(request,'signup.html')
        
        try:
            if User.objects.get(username=email):
               messages.info(request,"Email is Taken")
               return render(request,'signup.html')
        except Exception as identifier:
            pass
        user = User.objects.create_user(username = email,email=email,password=password)
        user.is_active=False
        user.save()
        email_subject="Activate Your Account"
        message=render_to_string('activate.html',{
            'user':user,
            'domain':'127.0.0.1:8000',
            'uid':urlsafe_base64_encode(force_str(user.pk).encode('utf-8')),
            'token':generate_token.make_token(user)

        })
        messages.success(request,f"Activate Your Account by clicking the link in your gmail {message}")
        return redirect('/auth/login/')
    return render(request,"signup.html")

class ActivateAccountView(View):
    def get(self,request,uidb64,token):
        try:
            uid=force_str(urlsafe_base64_decode(uidb64))
            user=User.objects.get(pk=uid)
        except Exception as identifier:
            user=None
        if user is not None and generate_token.check_token(user,token):
            user.is_active=True
            user.save()
            messages.info(request,"Account Activated Successfully")
            return redirect('/auth/login')
        return render(request,'activatefail.html')

def handlelogin(request):
    return render(request,"login.html")
    
def handlelogout(request):
    return redirect('/auth/login')