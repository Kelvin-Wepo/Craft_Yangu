from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User

class LoginForm(AuthenticationForm):
    username = forms.CharField(widget = forms.TextInput(attrs = {
        'placeholder' : 'Your Username',
        'class' : 'w-full py-4 px-6 rounded-xl',
    }))
    password = forms.CharField(widget = forms.PasswordInput(attrs = {
        'placeholder' : 'Your Password',
        'class' : 'w-full py-4 px-6 rounded-xl',
    }))

class SignupForm(UserCreationForm):
    email = forms.EmailField(max_length=254, required=True, widget=forms.EmailInput(attrs={
        'placeholder': 'Your Email Address',
        'class': 'w-full py-4 px-6 rounded-xl',
    }))
    phone_number = forms.CharField(max_length=15, required=True, widget=forms.TextInput(attrs={
        'placeholder': 'Your Phone Number',
        'class': 'w-full py-4 px-6 rounded-xl',
    }))

    class Meta:
        model = User
        fields = ('username', 'email', 'password1', 'password2')

    def __init__(self, *args, **kwargs):
        super(SignupForm, self).__init__(*args, **kwargs)
        self.fields['username'].widget.attrs.update({
            'placeholder': 'Your Username',
            'class': 'w-full py-4 px-6 rounded-xl',
        })
        self.fields['password1'].widget.attrs.update({
            'placeholder': 'Your Password',
            'class': 'w-full py-4 px-6 rounded-xl',
        })
        self.fields['password2'].widget.attrs.update({
            'placeholder': 'Confirm Password',
            'class': 'w-full py-4 px-6 rounded-xl',
        })

    def save(self, commit=True):
        user = super(SignupForm, self).save(commit=False)
        user.email = self.cleaned_data['email']
        if commit:
            user.save()
        return user

class OTPVerificationForm(forms.Form):
    otp = forms.CharField(label='OTP', max_length=6, min_length=6, widget=forms.TextInput(attrs={'class': 'form-control'}))