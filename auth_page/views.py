from django.conf import settings
from django.core.urlresolvers import reverse
from django.contrib.auth import authenticate ,  REDIRECT_FIELD_NAME
from django.contrib.auth import login as django_login
from django.contrib.auth import logout as django_logout
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.models import User
from django.contrib.auth.views import login as django_login_view
from django.contrib.auth.views import password_reset
from django.contrib.sites.models import Site
from django.core.mail import send_mail
from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.template.loader import render_to_string
from django.utils.hashcompat import sha_constructor
from forms import ProfileForm, UserCreationFormExtended, AuthenticationFormExtended
from models import Email
from random import random
from django.utils.translation import ugettext, ugettext_lazy as _
import hashlib
from datetime import datetime , timedelta
from django.utils import timezone
from django.views.decorators.debug import sensitive_post_parameters
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.contrib.sites.models import get_current_site
from django.template.response import TemplateResponse
from django.utils.http import base36_to_int, is_safe_url

"""def login(request):
    return django_login_view(request, 'login.html')
"""

@sensitive_post_parameters()
@csrf_protect
@never_cache
def login(request, template_name='login.html',
          redirect_field_name=REDIRECT_FIELD_NAME,
          authentication_form=AuthenticationFormExtended,
          current_app=None, extra_context=None):
    """
    Displays the login form and handles the login action.
    """
    redirect_to = request.REQUEST.get(redirect_field_name, '')

    if request.method == "POST":
        form = authentication_form(data=request.POST)
        if form.is_valid():
            # Ensure the user-originating redirection url is safe.
            """if not is_safe_url(url=redirect_to, host=request.get_host()):
                redirect_to = resolve_url(settings.LOGIN_REDIRECT_URL)
            """
            # Okay, security check complete. Log the user in.
            django_login(request, form.get_user())

            if request.session.test_cookie_worked():
                request.session.delete_test_cookie()

            return HttpResponseRedirect(redirect_to)
    else:
        form = authentication_form(request)

    request.session.set_test_cookie()

    current_site = get_current_site(request)

    context = {
        'form': form,
        redirect_field_name: redirect_to,
        'site': current_site,
        'site_name': current_site.name,
    }
    if extra_context is not None:
        context.update(extra_context)
    return TemplateResponse(request, template_name, context,
                            current_app=current_app)



def register(request):
    if request.method == 'POST':
        form = UserCreationFormExtended(request.POST)
        if form.is_valid():
            
            user = User.objects.create_user(form.cleaned_data['username'],
                                    form.cleaned_data['email'],
                                    password=form.cleaned_data['password1'])
            user.first_name = form.cleaned_data['first_name']
            user.last_name = form.cleaned_data['last_name']
            user.save()
            
            #form.save()
            print str(user)
            
            new_user = authenticate(username = request.POST.get('username'), password = request.POST.get('password1'))
            #django_login(request, new_user)
            send_registration_confirmation(new_user)
            
            next = request.POST.get('next', '/')
            return render_to_response('account_confirmed.html',
                                      { 'next': next},
                                        context_instance = RequestContext(request))
            
            #return HttpResponseRedirect(request.POST.get('next', '/'))
        else:            
            next = request.POST.get('next', '/')
            return render_to_response('register.html',
                                      {'form': form,
                                        'next': next},
                                        context_instance = RequestContext(request))
    else:
        form = UserCreationFormExtended()
        next = request.GET.get('next', '/')
        return render_to_response('register.html',
                                  {'form': form,
                                    'next': next},
                                    context_instance = RequestContext(request))
  
def send_registration_confirmation(user):
    title = _("Account confirmation")
    
    current_site = Site.objects.get_current()
                    
    activate_url = u"http://%s%s%s%s%s" % (unicode(current_site.domain),
                                             '/auth_page/confirm_registration/',
                                             str(confirmation_code(user)),
                                             '/',
                                             user.username)
    
    content = "%s %s %s %s %s" % ( _('Welcome'),
                                   user.first_name,
                                   user.last_name,
                                   _('pleas confirm your account by url:'),
                                   activate_url)
    send_mail(title, content, 'marcinradon@recoded.co', [user.email], fail_silently=False)

def confirmation_code(user):
    h = hashlib.md5();
    h.update(user.username)
    h.update('confirm')
    h.update(user.email)
    print h.hexdigest()
    return h.hexdigest()

def confirm_registration(request, code, username):
    try:
        user = User.objects.get(username=username)
        print datetime.now()
        print timedelta(days=1)
        print (datetime.now()-timedelta(days=1))
        
        if confirmation_code(user) == code and user.date_joined > timezone.make_aware((datetime.now()-timedelta(days=1)), timezone.get_default_timezone()):
            user.is_active = True
            user.save()
            user.backend='django.contrib.auth.backends.ModelBackend' 
            django_login(request, user)
            return HttpResponseRedirect(request.POST.get('next', '/'))
    except Exception as e:
        print e
        return HttpResponseRedirect(request.POST.get('next', '/'))


def logout(request):
    django_logout(request)
    return  HttpResponseRedirect(request.GET.get('next', '/'))
    

def profile(request):
    """
    Form for modifying and adding profile values
    """
    if request.method == 'POST':
        form = ProfileForm(request.POST,
                           instance = request.user)
        
        email = request.POST.get('email', '')
        if not email == '' and not email == request.user.email:
            #confirm the email
            salt = sha_constructor(str(random())).hexdigest()[:5]
            confirmation_key = sha_constructor(salt + email).hexdigest()
            current_site = Site.objects.get_current()
       
            path = reverse('confirm_email',
                            args=[confirmation_key])
                
            activate_url = u"http://%s%s" % (unicode(current_site.domain),
                                             path)
            context = {
                "user": request.user,
                "activate_url": activate_url,
                "current_site": current_site,
                "confirmation_key": confirmation_key,
            }
            subject = render_to_string(
                "email_confirmation_subject.txt",
                context)
        
            # remove superfluous line breaks
            subject = "".join(subject.splitlines())
            message = render_to_string(
                "email_confirmation_message.txt",
                context)
            print email
            send_mail(subject,
                      message,
                      getattr(settings,
                              'DEFAULT_FROM_EMAIL',
                              'do-not-reply@%s' % current_site),
                      [email])
        
            Email.objects.create(
                owner = request.user,
                email = email,
                email_is_verified = False,
                sent = datetime.now(),
                confirmation_key = confirmation_key)
        
        form.save()
        return HttpResponseRedirect(request.POST.get('next', '/'))

    else:
        form = ProfileForm(instance = request.user)
        next = request.GET.get('next', '/')
        return render_to_response('profile.html',
                                  {'form': form,
                                   'next': next},
                                  context_instance = RequestContext(request))
        
def confirm_email(request, confirmation_key):
    print "confirm_email"
    try:
        email = Email.objects.get(confirmation_key = confirmation_key,
                                  email_is_verified = False)
        email.email_is_verified = True
        email.save()
        return render_to_response('email_confirmed.html',
                                  {'email': email})
    except Email.DoesNotExist:
        return HttpResponse('No email found for this link')

def retrieve_new_password(request):
    
    if request.method == 'POST':
        email = request.POST['email']
        try:
            verified_email = Email.objects.get(email = email,
                                               email_is_verified = True)
            return password_reset(request)
        except Email.DoesNotExist:
            return render_to_response('retrieve_new_password.html',
                                      {'errors': 'The email you entered was not found or it has never been verified'},
                                      context_instance = RequestContext(request))
    else:
        return render_to_response('retrieve_new_password.html',
                                  context_instance = RequestContext(request))
    