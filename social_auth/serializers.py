from rest_framework import serializers
from . import google
from .register import register_social_user
import os
from rest_framework.exceptions import AuthenticationFailed
from django.conf import settings




class GoogleSocialAuthSerializer(serializers.Serializer):
    print("heloooooooooooooooooooooooooooooooooo")
    auth_token = serializers.CharField()
    print("auth tokennnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn",auth_token)

    def validate_auth_token(self, auth_token):
        print("hiiiiiiiiiiiiiiiiiiiiiiiii")
        user_data = google.Google.validate(auth_token)
        print("user dataaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",user_data)
        try:
            user_data['sub']
            print("2222222222222222222222222222222222222222",user_data)
        except:
            raise serializers.ValidationError(
                'The token is invalid or expired. Please login again.'
            )

        if user_data['aud'] != settings.GOOGLE_CLIENT_ID:

            raise AuthenticationFailed('oops, who are you?')

        user_id = user_data['sub']
        email = user_data['email']
        name = user_data['name']
        provider = 'google'

        return register_social_user(
            provider=provider, user_id=user_id, email=email, name=name)


