# -*- coding: utf-8 -*-
from django.conf.urls import patterns
from django.conf.urls import url

urlpatterns = patterns('auth_page.views',
            url(r'^login/$',
                'login',
                name="login"),
            url(r'^logout/$',
                'logout',
                name="logout"),
            url(r'^profile/$',
                'profile',
                name="profile"),
            url(r'^register/$',
                'register',
                name="register"),
            url(r'^confirm/(\w+)$',
                'confirm_email',
                name="confirm_email"),
            url(r'^confirm_registration/(?P<code>\w+)/(?P<username>\w+)$',
                'confirm_registration',
                name="confirm_retistration"),
            url(r'^retrieve_new_password/$',
                'retrieve_new_password',
                name="retrieve_new_password"),
        )

urlpatterns += patterns('',
            (r'^reset_password_done/$',
             'django.contrib.auth.views.password_reset_done'),
            (r'^reset_password_confirm/(?P<uidb36>[0-9A-Za-z]+)-(?P<token>.+)/$',
             'django.contrib.auth.views.password_reset_confirm'),
            (r'^reset_password_complete/$',
             'django.contrib.auth.views.password_reset_complete'),
            )