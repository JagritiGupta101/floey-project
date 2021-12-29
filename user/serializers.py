from .models import *
from rest_framework import serializers
from django.contrib.auth.hashers import make_password

from .models import User
from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode

from rest_framework.exceptions import AuthenticationFailed

# Django imports
from django.conf import settings

# Inside App imports
# from .services import google_auth
# from .register import register_social_user



# class GoogleSocialAuthSerializer(serializers.Serializer):
#     '''
#     Handles serialization of Google related data

#     '''

#     auth_token = serializers.CharField()

#     def validate_auth_token(self, auth_token):
#         '''
#         Validate the auth token provided by Google with the Google Python Client Library
#         '''
#         print("Length Token: ",len(auth_token))
#         user_data = google_auth.Google.validate(auth_token)
#         print("User Data, ",user_data)
#         try:
#             user_data['sub']
#         except:
#             raise serializers.ValidationError('The token is invalid or expired. Please login again')

#         if user_data['aud'] != settings.GOOGLE_CLIENT_ID:
#             raise AuthenticationFailed('We are unable to recognise you!')

#         user_id = user_data['sub']
#         email = user_data['email']
#         name = user_data['name']
#         provider = 'google'
#         request = self.context['request']
#         return register_social_user(
#             request=request, provider=provider, user_id=user_id, email=email, name=name
#         ) 



class GymManagerSerializer(serializers.ModelSerializer):
    class Meta:
        model = GymManager
        fields = '__all__'

class UserGymSer(serializers.ModelSerializer):
    class Meta:
        model = UserSelectedGym
        fields = '__all__'

class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = '__all__'
        
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'
        # fields = ("first_name", "last_name", "email", "phone_number","dob","gender","password")

    # class Meta:
    
    #     model = User
    #     fields = '__all__'
    
    def validate_password(self, password) -> str:
        return make_password(password)
class UserHistorySerializer(serializers.ModelSerializer):
    class Meta:
    
        model = UserHistory
        fields = '__all__'

class UserclassSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserClass
        fields = '__all__'

# ********course********

class UsercourseSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserCourse
        fields = '__all__'

class SubscriptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Subscription
        fields='__all__'
        
class SubAdminSerializer(serializers.ModelSerializer):
 
    class Meta:
        model = User
        fields = ("first_name", "last_name", "email", "password", "is_active","is_staff")

    def validate_password(self, password) -> str:
        """ A function to save the password for storing the values """
        return make_password(password)

class GymMemberSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("user_role","first_name", "last_name", "email", "password", "profile_picture","dob","gender","is_active","is_staff")
    def validate_password(self, password) -> str:
        """ A function to save the password for storing the values """
        return make_password(password)    


class RolesNPermsSer(serializers.ModelSerializer):
    class Meta:
        model = RoleWisePermissions
        fields = '__all__'


class EmailVerificationSerializer(serializers.ModelSerializer):
    # print("emailverificationserializerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr")
    token = serializers.CharField(max_length=555)
    # print("tokenserializerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr",token)
    # print("hiiiiiiiiiiiiiiiiiiiiiiiiiiiii")
    class Meta:
        model = User
        fields = ['token']

class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=2)

    redirect_url = serializers.CharField(max_length=500, required=False)

    class Meta:
        fields = ['email']


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(
        min_length=6, max_length=68, write_only=True)
    token = serializers.CharField(
        min_length=1, write_only=True)
    uidb64 = serializers.CharField(
        min_length=1, write_only=True)

    class Meta:
        fields = ['password', 'token', 'uidb64']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')

            id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed('The reset link is invalid', 401)

            user.set_password(password)
            user.save()

            return (user)
        except Exception as e:
            raise AuthenticationFailed('The reset link is invalid', 401)
        return super().validate(attrs)


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    default_error_message = {
        'bad_token': ('Token is expired or invalid')
    }

    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):

        try:
            RefreshToken(self.token).blacklist()

        except TokenError:
            self.fail('bad_token')