from django.forms import ModelForm
from django.contrib.auth.models import User
from django import forms
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.utils.translation import ugettext, ugettext_lazy as _
from django.contrib.auth.hashers import check_password
from django.db.models import Q


class ProfileForm(ModelForm):
    
    class Meta:
        model = User
        fields = ('first_name',
                  'last_name',
                  'email')
        
class UserCreationFormExtended(UserCreationForm):
    """
    A form that creates a user, with no privileges, from the given username and
    password.
    """
    
    email = forms.EmailField(label=_("E-mail"))
    first_name = forms.CharField(label=_("First name"))
    last_name = forms.CharField(label=_("Last name"))
    
    class Meta:
        model = User
        fields = ("username","email","first_name","last_name")
        
    def save(self, commit=True):
        user = super(UserCreationForm, self).save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        user.first_name = self.cleaned_data["first_name"]
        user.last_name = self.cleaned_data["last_name"]
        user.email = self.cleaned_data["email"]
            
        if commit:
            user.save()
        return user
    
class AuthenticationFormExtended(AuthenticationForm):
    
    username = forms.CharField(label=_('username/e-mail'),max_length=254)
    
    error_messages = {
        'invalid_login': _("Please enter a correct user name or e-mail and password. "
                           "Note that both fields may be case-sensitive."),
        'no_cookies': _("Your Web browser doesn't appear to have cookies "
                        "enabled. Cookies are required for logging in."),
        'inactive': _("This account is inactive."),
    }
    
    def is_valid(self):
        
        valid = super(AuthenticationFormExtended, self).is_valid()
        if valid:
            return True;
        
        # so far so good, get this user based on the username or email
        try:
            user = User.objects.get(
                Q(username=self.data['username']) | Q(email=self.data['username'])
            )
 
        # no user with this username or email address
        except User.DoesNotExist:
            self._errors['no_user'] = _('User does not exist')
            return False
 
        # verify the passwords match
        if not check_password(self.data['password'], user.password):
            self._errors['invalid_password'] = _('Password is invalid')
            return False
 
        # all good
        return True
    
    def get_user(self):
        
        if self.is_valid():
            print "self.is_valid()"
            user = User.objects.get(
                Q(username=self.data['username']) | Q(email=self.data['username'])
                )
            user.backend='django.contrib.auth.backends.ModelBackend'
            return user
        else:
            raise  User.DoesNotExist()
    