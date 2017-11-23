
from django.conf.urls import url
from django.conf import settings
from django.conf.urls.static import static

from django.contrib.auth import views as auth_views
from doubletrouble_chat.accounts import views as accounts_views
from rest_framework.authtoken import views as rest_framework_views

urlpatterns = [
    # default django authentication login/logout pages
	url(r'^login/$', auth_views.login, name='login'),
	url(r'^logout/$', auth_views.logout, {'next_page': '/'}, name='logout'),
    url(r'^signup/$', accounts_views.signup, name='signup'),
    # Session Login
    #url(r'^login/$', local_views.login_form, name='login_form'),
    #url(r'^logout/$', local_views.logout_user, name='logout'),
    url(r'^auth/$', accounts_views.get_auth_token, name='get_auth_token'),
    url(r'^get_auth_token/$', rest_framework_views.obtain_auth_token, name='get_auth_token'),
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
