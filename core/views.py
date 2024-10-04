import logging
from django.shortcuts import render, redirect
from django.contrib.auth import login
from django.contrib import messages
from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist
from item.models import Category, Item
from django.conf import settings
from .forms import SignupForm, OTPVerificationForm
from .models import Profile
import africastalking
import random



logger = logging.getLogger(__name__)

# Initialize AfricasTalking
africastalking.initialize(
    username=settings.AFRICASTALKING_USERNAME,
    api_key=settings.AFRICASTALKING_API_KEY
)
sms = africastalking.SMS

def generate_otp():
    return str(random.randint(100000, 999999))

def send_sms(phone_number, message):
    try:
        response = sms.send(message, [phone_number], sender_id="20880")
        logger.info(f"SMS sent to {phone_number}. Response: {response}")
        return response
    except Exception as e:
        logger.error(f"Error sending SMS to {phone_number}: {str(e)}")
        return None

def send_otp(phone_number, otp):
    message = f"Your OTP is: {otp}"
    return send_sms(phone_number, message)

def send_welcome_message(phone_number, username):
    message = f"Hello {username}, thank you for creating an account with us. To explore our marketplace please visit www.craftyangu.com."
    return send_sms(phone_number, message)

def signup(request):
    if request.method == 'POST':
        form = SignupForm(request.POST)
        if form.is_valid():
            try:
                user = form.save(commit=False)
                user.is_active = False  # User won't be able to log in until OTP is verified
                user.save()
                
                # Get or create profile
                profile, created = Profile.objects.get_or_create(user=user)
                
                # Save phone number to profile
                phone_number = form.cleaned_data.get('phone_number')
                profile.phone_number = phone_number
                
                # Generate and save OTP
                otp = generate_otp()
                profile.otp = otp
                profile.save()
                
                # Send OTP
                if send_otp(phone_number, otp):
                    messages.success(request, "OTP sent successfully. Please check your phone.")
                    return redirect('core:verify_otp', user_id=user.id)
                else:
                    messages.error(request, "Failed to send OTP. Please try again.")
                    user.delete()  # Delete the user if OTP sending fails
                    return redirect('core:signup')
                
            except Exception as e:
                logger.error(f"Error during signup: {str(e)}")
                messages.error(request, "An error occurred during signup. Please try again.")
                return redirect('core:signup')
        else:
            messages.error(request, "Please correct the errors below.")
    else:
        form = SignupForm()
    
    return render(request, 'core/signup.html', {'form': form})

def verify_otp(request, user_id):
    try:
        user = User.objects.get(id=user_id)
    except ObjectDoesNotExist:
        messages.error(request, "User not found.")
        return redirect('core:signup')

    if request.method == 'POST':
        form = OTPVerificationForm(request.POST)
        if form.is_valid():
            otp = form.cleaned_data['otp']
            if otp == user.profile.otp:
                user.is_active = True
                user.save()
                login(request, user)
                
                # Send welcome message
                if send_welcome_message(user.profile.phone_number, user.username):
                    messages.success(request, "Welcome! Your account has been verified.")
                else:
                    messages.warning(request, "Your account is verified, but we couldn't send a welcome message.")
                
                return redirect('core:index')
            else:
                form.add_error('otp', 'Invalid OTP')
                messages.error(request, "Invalid OTP. Please try again.")
    else:
        form = OTPVerificationForm()

    return render(request, 'core/verify_otp.html', {'form': form})

def index(request):
    items = Item.objects.filter(is_sold=False)[:6]
    categories = Category.objects.all()

    return render(request, 'core/index.html', {
        'categories': categories,
        'items': items,
    })

def contact(request):
    return render(request, 'core/contact.html')
