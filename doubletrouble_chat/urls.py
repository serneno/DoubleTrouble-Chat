"""doubletrouble_chat URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.11/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url, include
from django.contrib import admin
from django.contrib.auth import views as auth_views
from rest_framework import routers
from doubletrouble_chat.client import views as client_views
from rest_framework_jwt.views import obtain_jwt_token, refresh_jwt_token, verify_jwt_token

router = routers.DefaultRouter()
router.register(r'users', client_views.UserViewSet)
router.register(r'groups', client_views.GroupViewSet)


urlpatterns = [
	url(r'^', include(router.urls)),
	url(r'^api-auth/', include('rest_framework.urls', namespace='rest_framework')),
	url(r'^login/$', auth_views.login, name='login'),
	url(r'^logout/$', auth_views.logout, name='logout'),
	url(r'^admin/', admin.site.urls),
	# user auth urls
	#url(r'^accounts/', include('doubletrouble_chat.accounts.urls', namespace='accounts')),
	# jwt token urls
	url(r'^api-token-auth/', obtain_jwt_token),
	url(r'^api-token-refresh/', refresh_jwt_token),
	url(r'api-token-verify/', verify_jwt_token),
]
