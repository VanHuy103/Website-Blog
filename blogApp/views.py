import datetime
import json
import warnings
from unicodedata import category
from urllib.parse import urlparse, urlunparse

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import (REDIRECT_FIELD_NAME, authenticate,
                                 get_user_model, login, logout,
                                 update_session_auth_hash)
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import (AuthenticationForm, PasswordChangeForm,
                                       PasswordResetForm, SetPasswordForm,
                                       UserCreationForm)
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.http import HttpResponse, HttpResponseRedirect, QueryDict
from django.shortcuts import redirect, render, resolve_url
from django.urls import reverse, reverse_lazy
from django.utils.decorators import method_decorator
from django.utils.deprecation import RemovedInDjango50Warning
from django.utils.http import (url_has_allowed_host_and_scheme,
                               urlsafe_base64_decode)
from django.utils.translation import gettext_lazy as _
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic.base import TemplateView
from django.views.generic.edit import FormView
from rest_framework import generics, status


from blogApp.forms import (AddAvatar, SaveCategory, SavePost, UpdateProfile,
                           UpdateProfileAvatar, UpdateProfileMeta,
                           UserRegistration)
from blogApp.models import Category, Post, UserProfile

# from .serializers import ChangePasswordSerializer

UserModel = get_user_model()


category_list = Category.objects.exclude(status=2).all()
context = {
    'page_title': 'Simple Blog Site',
    'category_list': category_list,
    'category_list_limited': category_list[:3]
}


# login


def login_user(request):
    logout(request)
    resp = {"status": 'failed', 'msg': ''}
    username = ''
    password = ''
    if request.POST:
        username = request.POST['username']
        password = request.POST['password']

        user = authenticate(username=username, password=password)
        if user is not None:
            if user.is_active:
                login(request, user)
                resp['status'] = 'success'
            else:
                resp['msg'] = "Incorrect username or password"
        else:
            resp['msg'] = "Incorrect username or password"
    return HttpResponse(json.dumps(resp), content_type='application/json')

# Logout


def logoutuser(request):
    logout(request)
    return redirect('/')


def home(request):
    context['page_title'] = 'Home'
    posts = Post.objects.filter(status=1).all()
    context['posts'] = posts
    print(request.user)
    return render(request, 'home.html', context)


def registerUser(request):
    user = request.user
    if user.is_authenticated:
        return redirect('home-page')
    context['page_title'] = "Register User"
    if request.method == 'POST':
        data = request.POST
        form = UserRegistration(data)
        if form.is_valid():
            form.save()
            newUser = User.objects.all().last()
            try:
                profile = UserProfile.objects.get(user=newUser)
            except:
                profile = None
            if profile is None:
                UserProfile(user=newUser, dob=data['dob'], contact=data['contact'],
                            address=data['address'], avatar=request.FILES['avatar']).save()
            else:
                UserProfile.objects.filter(id=profile.id).update(
                    user=newUser, dob=data['dob'], contact=data['contact'], address=data['address'])
                avatar = AddAvatar(
                    request.POST, request.FILES, instance=profile)
                if avatar.is_valid():
                    avatar.save()
            username = form.cleaned_data.get('username')
            pwd = form.cleaned_data.get('password1')
            loginUser = authenticate(username=username, password=pwd)
            login(request, loginUser)
            return redirect('home-page')
        else:
            context['reg_form'] = form

    return render(request, 'register.html', context)


@login_required
def profile(request):
    context = {
        'page_title': "My Profile"
    }

    return render(request, 'profile.html', context)


@login_required
def update_profile(request):
    context['page_title'] = "Update Profile"
    user = User.objects.get(id=request.user.id)
    profile = UserProfile.objects.get(user=user)
    context['userData'] = user
    context['userProfile'] = profile
    if request.method == 'POST':
        data = request.POST
        # if data['password1'] == '':
        # data['password1'] = '123'
        form = UpdateProfile(data, instance=user)
        if form.is_valid():
            form.save()
            form2 = UpdateProfileMeta(data, instance=profile)
            if form2.is_valid():
                form2.save()
                messages.success(
                    request, "Your Profile has been updated successfully")
                return redirect("profile")
            else:
                # form = UpdateProfile(instance=user)
                context['form2'] = form2
        else:
            context['form1'] = form
            form = UpdateProfile(instance=request.user)
    return render(request, 'update_profile.html', context)


@login_required
def update_avatar(request):
    context['page_title'] = "Update Avatar"
    user = User.objects.get(id=request.user.id)
    context['userData'] = user
    context['userProfile'] = user.profile
    img = user.profile.avatar.url

    context['img'] = img
    if request.method == 'POST':
        form = UpdateProfileAvatar(request.POST, request.FILES, instance=user)
        if form.is_valid():
            form.save()
            messages.success(
                request, "Your Profile has been updated successfully")
            return redirect("profile")
        else:
            context['form'] = form
            form = UpdateProfileAvatar(instance=user)
    return render(request, 'update_avatar.html', context)

# Category


@login_required
def category_mgt(request):
    categories = Category.objects.all()
    context['page_title'] = "Category Management"
    context['categories'] = categories
    return render(request, 'category_mgt.html', context)


@login_required
def manage_category(request, pk=None):
    # category = Category.objects.all()
    if pk == None:
        category = {}
    elif pk > 0:
        category = Category.objects.filter(id=pk).first()
    else:
        category = {}
    context['page_title'] = "Manage Category"
    context['category'] = category

    return render(request, 'manage_category.html', context)


@login_required
def save_category(request):
    resp = {'status': 'failed', 'msg': ''}
    if request.method == 'POST':
        category = None
        if not request.POST['id'] == '':
            category = Category.objects.filter(id=request.POST['id']).first()
        if not category == None:
            form = SaveCategory(request.POST, instance=category)
        else:
            form = SaveCategory(request.POST)
    if form.is_valid():
        form.save()
        resp['status'] = 'success'
        messages.success(request, 'Category has been saved successfully')
    else:
        for field in form:
            for error in field.errors:
                resp['msg'] += str(error + '<br>')
        if not category == None:
            form = SaveCategory(instance=category)

    return HttpResponse(json.dumps(resp), content_type="application/json")


@login_required
def delete_category(request):
    resp = {'status': 'failed', 'msg': ''}
    if request.method == 'POST':
        id = request.POST['id']
        try:
            category = Category.objects.filter(id=id).first()
            category.delete()
            resp['status'] = 'success'
            messages.success(
                request, 'Category has been deleted successfully.')
        except Exception as e:
            raise print(e)
    return HttpResponse(json.dumps(resp), content_type="application/json")

# Post


@login_required
def post_mgt(request):
    if request.user.profile.user_type == 1:
        posts = Post.objects.all()
    else:
        posts = Post.objects.filter(author=request.user).all()

    context['page_title'] = "post Management"
    context['posts'] = posts
    return render(request, 'post_mgt.html', context)


@login_required
def manage_post(request, pk=None):
    # post = post.objects.all()
    if pk == None:
        post = {}
    elif pk > 0:
        post = Post.objects.filter(id=pk).first()
    else:
        post = {}
    context['page_title'] = "Manage post"
    context['post'] = post

    return render(request, 'manage_post.html', context)


@login_required
def save_post(request):
    resp = {'status': 'failed', 'msg': ''}
    if request.method == 'POST':
        post = None
        if not request.POST['id'] == '':
            post = Post.objects.filter(id=request.POST['id']).first()
        if not post == None:
            form = SavePost(request.POST, request.FILES, instance=post)
        else:
            form = SavePost(request.POST, request.FILES)
    if form.is_valid():
        form.save()
        resp['status'] = 'success'
        messages.success(request, 'Post has been saved successfully')
    else:
        for field in form:
            for error in field.errors:
                resp['msg'] += str(error + '<br>')
        if not post == None:
            form = SavePost(instance=post)

    return HttpResponse(json.dumps(resp), content_type="application/json")


@login_required
def delete_post(request):
    resp = {'status': 'failed', 'msg': ''}
    if request.method == 'POST':
        id = request.POST['id']
        try:
            post = Post.objects.filter(id=id).first()
            post.delete()
            resp['status'] = 'success'
            messages.success(request, 'Post has been deleted successfully.')
        except Exception as e:
            raise print(e)
    return HttpResponse(json.dumps(resp), content_type="application/json")


def view_post(request, pk=None):
    context['page_title'] = ""
    if pk is None:
        messages.error(request, "Unabale to view Post")
        return redirect('home-page')
    else:
        post = Post.objects.filter(id=pk).first()
        context['page_title'] = post.title
        context['post'] = post
    return render(request, 'view_post.html', context)


def post_by_category(request, pk=None):
    if pk is None:
        messages.error(request, "Unabale to view Post")
        return redirect('home-page')
    else:
        category = Category.objects.filter(id=pk).first()
        context['page_title'] = category.name
        context['category'] = category
        posts = Post.objects.filter(category=category).all()
        context['posts'] = posts
    return render(request, 'by_categories.html', context)


def categories(request):
    categories = Category.objects.filter(status=1).all()
    context['page_title'] = "Category Management"
    context['categories'] = categories
    return render(request, 'categories.html', context)


class PasswordContextMixin:
    extra_context = None

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update(
            {"title": self.title, "subtitle": None,
                **(self.extra_context or {})}
        )
        return context


class PasswordResetView(PasswordContextMixin, FormView):
    email_template_name = "registration/password_reset_email.html"
    extra_email_context = None
    form_class = PasswordResetForm
    from_email = None
    html_email_template_name = None
    subject_template_name = "registration/password_reset_subject.txt"
    success_url = reverse_lazy("password_reset_done")
    template_name = "registration/password_reset_form.html"
    title = _("Password reset")
    token_generator = default_token_generator

    @method_decorator(csrf_protect)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def form_valid(self, form):
        opts = {
            "use_https": self.request.is_secure(),
            "token_generator": self.token_generator,
            "from_email": self.from_email,
            "email_template_name": self.email_template_name,
            "subject_template_name": self.subject_template_name,
            "request": self.request,
            "html_email_template_name": self.html_email_template_name,
            "extra_email_context": self.extra_email_context,
        }
        form.save(**opts)
        return super().form_valid(form)


INTERNAL_RESET_SESSION_TOKEN = "_password_reset_token"


class PasswordResetDoneView(PasswordContextMixin, TemplateView):
    template_name = "registration/password_reset_done.html"
    title = _("Password reset sent")


class PasswordResetConfirmView(PasswordContextMixin, FormView):
    form_class = SetPasswordForm
    post_reset_login = False
    post_reset_login_backend = None
    reset_url_token = "set-password"
    success_url = reverse_lazy("password_reset_complete")
    template_name = "registration/password_reset_confirm.html"
    title = _("Enter new password")
    token_generator = default_token_generator

    @method_decorator(sensitive_post_parameters())
    @method_decorator(never_cache)
    def dispatch(self, *args, **kwargs):
        if "uidb64" not in kwargs or "token" not in kwargs:
            raise ImproperlyConfigured(
                "The URL path must contain 'uidb64' and 'token' parameters."
            )

        self.validlink = False
        self.user = self.get_user(kwargs["uidb64"])

        if self.user is not None:
            token = kwargs["token"]
            if token == self.reset_url_token:
                session_token = self.request.session.get(
                    INTERNAL_RESET_SESSION_TOKEN)
                if self.token_generator.check_token(self.user, session_token):
                    # If the token is valid, display the password reset form.
                    self.validlink = True
                    return super().dispatch(*args, **kwargs)
            else:
                if self.token_generator.check_token(self.user, token):
                    # Store the token in the session and redirect to the
                    # password reset form at a URL without the token. That
                    # avoids the possibility of leaking the token in the
                    # HTTP Referer header.
                    self.request.session[INTERNAL_RESET_SESSION_TOKEN] = token
                    redirect_url = self.request.path.replace(
                        token, self.reset_url_token
                    )
                    return HttpResponseRedirect(redirect_url)

        # Display the "Password reset unsuccessful" page.
        return self.render_to_response(self.get_context_data())

    def get_user(self, uidb64):
        try:
            # urlsafe_base64_decode() decodes to bytestring
            uid = urlsafe_base64_decode(uidb64).decode()
            user = UserModel._default_manager.get(pk=uid)
        except (
            TypeError,
            ValueError,
            OverflowError,
            UserModel.DoesNotExist,
            ValidationError,
        ):
            user = None
        return user

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["user"] = self.user
        return kwargs

    def form_valid(self, form):
        user = form.save()
        del self.request.session[INTERNAL_RESET_SESSION_TOKEN]
        if self.post_reset_login:
            login(self.request, user, self.post_reset_login_backend)
        return super().form_valid(form)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        if self.validlink:
            context["validlink"] = True
        else:
            context.update(
                {
                    "form": None,
                    "title": _("Password reset unsuccessful"),
                    "validlink": False,
                }
            )
        return context


class PasswordResetCompleteView(PasswordContextMixin, TemplateView):
    template_name = "registration/password_reset_complete.html"
    title = _("Password reset complete")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["login_url"] = resolve_url(settings.LOGIN_URL)
        return context


class PasswordChangeView(PasswordContextMixin, FormView):
    form_class = PasswordChangeForm
    success_url = reverse_lazy("password_change_done")
    template_name = "registration/password_change_form.html"
    title = _("Password change")

    @method_decorator(sensitive_post_parameters())
    @method_decorator(csrf_protect)
    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["user"] = self.request.user
        return kwargs

    def form_valid(self, form):
        form.save()
        # Updating the password logs out all other sessions for the user
        # except the current one.
        update_session_auth_hash(self.request, form.user)
        return super().form_valid(form)


class PasswordChangeDoneView(PasswordContextMixin, TemplateView):
    template_name = "registration/password_change_done.html"
    title = _("Password change successful")

    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)
