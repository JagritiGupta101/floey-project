# from django.shortcuts import render
import json
from datetime import date, datetime, timedelta
import calendar
from warnings import resetwarnings
import jwt
import pandas as pd
from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.contrib.sites.models import Site
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail
from django.http import Http404, HttpResponse, JsonResponse
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt
from gymprofile.serializers import *
from rest_framework import filters, generics, status, viewsets
from rest_framework.decorators import action
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView

from .models import *
from .serializers import *
from .utils import Util

from django.db import connection


class AdminCreateList(generics.ListAPIView):
    """
    class creates new sub admin on admin panel and list
    all admins present
    """

    search_fields = ["email", "first_name", "last_name"]
    filter_backends = (filters.SearchFilter,)
    queryset = User.objects.filter(is_superuser=True).order_by('email')
    serializer_class = SubAdminSerializer
    


    def filter_queryset(self, queryset):
        """
        filter queryset according to search fields
        """
        
        for backend in list(self.filter_backends):
            queryset = backend().filter_queryset(self.request, queryset, self)
        return queryset

    # @csrf_exempt
    def post(self, request):
        """
        create api for sub admin
        """
        
        if User.objects.filter(email=request.data.get("email")).exists():
            return Response("User with this email already exists, Please use differnt email ID",status=status.HTTP_409_CONFLICT)
        request_data = request.data
        # if request_data.get("first_name"):
        #     name = request_data.pop("name")
        #     request_data["first_name"] = name.split()[0]
        #     request_data["last_name"] = " ".join(name.split()[1:])

        # permissions = request_data.pop("permissions")
        # permissions =RoleWisePermissions.objects.get(for_role=request_data.get('role')).permissions_list
        serializer = self.get_serializer(data=request_data)
        try:
            if serializer.is_valid(raise_exception=True):
                admin_user = serializer.save(is_superuser=True)
                user = User.objects.filter(uuid=str(admin_user.uuid)).first()
                # admin_pmsn = AdminPermissions(userinfo=user, perm_role=permissions)
                # admin_pmsn.save()
                # data['admin_permissions'] =
                return Response( {
                    "uuid": admin_user.uuid,
                    "email": admin_user.email,
                    "is_active": admin_user.is_active,
                    # "permissions": permissions
                })
        except Exception as e:
            print(str(e))
            return Response( "Something went wrong in creating admin", status=status.HHTTP_400_BAD_REQUEST)

    def get(self, request):
        """
        get list of all sub admins
        """

        queryset = self.filter_queryset(self.get_queryset()).values("uuid", "email", "is_active", "first_name", "last_name")

        return Response(queryset)

class RolePermsAPI(viewsets.ModelViewSet):
    queryset = RoleWisePermissions.objects.all()
    serializer_class = RolesNPermsSer
    
    def list(self, request):
        
        data = request.GET
        query = RoleWisePermissions.objects.filter(gym=data.get('gym'))
        context=[]
        for i in query:
            ser = RolesNPermsSer(i).data
            role = i.for_role.user_roles
            ser.update({
                'for_role':role
            })
            context.append(ser)
        return Response(context)
       
    def create(self,request):
        
        data = request.data
        data['permissions_list'] = ','.join(data.get('permissions_list'))
        if RoleWisePermissions.objects.filter(for_role=data['for_role'],gym = data['gym']).exists():
            obj = RoleWisePermissions.objects.filter(for_role=data['for_role'],gym = data['gym'])[0]
            ser = RolesNPermsSer(obj,data=data,partial=True)
            if ser.is_valid(raise_exception=True):
                ser.save()
                return Response(ser.data)
            return Response(ser.errors)
        else:
            
            ser = RolesNPermsSer(data = data)
            if ser.is_valid():
                ser.save()
                return Response(ser.data)
            return Response(ser.errors)

    def retrieve(self,request,pk):
        query = RoleWisePermissions.objects.get(uuid = pk)
        ser = RolesNPermsSer(query).data
        role = query.for_role.user_roles
        ser.update({
            'for_role':role
        })
        return Response(ser)

class AdminLoginView(APIView):
    # authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication)
    def post(self, request):
        
        data = request.data
        if User.objects.filter(email=request.data.get('email')).exists():
            user = User.objects.get(email=request.data.get('email'))
           
            if user.check_password(request.data.get('password')):
                if GymManager.objects.filter(owner=user.uuid).exists():
                    owner = GymManager.objects.filter(owner=user.uuid)[0]
                    ser = GymManagerSerializer(owner).data
                    context = {
                        'results':data,
                        'uuid':user.uuid,
                        'first_name':user.first_name,
                        'last_name':user.last_name,
                        'gym':owner.gym.uuid,
                        # 'perms':(AdminPermissions.objects.get(userinfo=user.uuid).perm_role.permissions_list).split(',')
                        }
                    # print(context['perms'])
                    return Response(context)
                else:
                    employee =GymManager.objects.filter(employee=user)[0]
                    ser = GymManagerSerializer(employee).data
                    context = {
                        'results':data,
                        'uuid':user.uuid,
                        'first_name':user.first_name,
                        'last_name':user.last_name,
                        'gym':employee.gym.uuid,
                        # 'perms':(AdminPermissions.objects.get(userinfo=user.uuid).perm_role.permissions_list).split(',')
                        }
                    # print(context['perms'])
                    return Response(context)
            return Response("Password is incorrect", status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response("User does not exist", status=status.HTTP_404_NOT_FOUND)

class AdminAction(APIView):
    # permission_classes = [permissions.IsAdminUser]

    def delete(self, request, pk):
        """
        delete an admin
        """

        if not User.objects.filter(uuid=pk).exists():
            return Response("No admin found with this id")

        User.objects.get(uuid=pk).delete()
        return Response("Admin deleted")

    def put(self, request, pk):
        """
        update creds of an admin
        """

        data = request.data
        if not User.objects.filter(uuid=pk).exists():
            return Response("No admin found with this id")
        admin_user = User.objects.get(uuid=pk)

       
        # if data.get("permissions"):
        #     ap = AdminPermissions.objects.get(user=pk)
        #     ap.admin_permissions = data.get("permissions")
        #     ap.save()


        serializer = SubAdminSerializer(admin_user, data=data, partial=True)
        if serializer.is_valid(raise_exception=True):
            admin = serializer.save()

            if "is_active" in data.keys() and eval(data.get("is_active")):
                return Response({'success':"Activated"}, status=status.HTTP_200_OK)

            elif "is_active" in data.keys() and not eval(data.get("is_active")):
                return Response({'False':"Deactivated"}, status=status.HTTP_200_OK)

            return Response( {
                "uuid": admin.uuid,
                "email": admin.email,
                "is_active": admin.is_active
            })
    
        # except Exception as e:
        return Response({'error':"Something went wrong in updating admin"}, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, pk):
        """
        get details of an admin
        """

         
        if not User.objects.filter(uuid=pk).exists():
            return Response({'error':"No admin found with this ID"}, status=status.HTTP_404_NOT_FOUND)
        # context={}

        u = User.objects.filter(uuid=pk).values("email", "uuid", "is_active", "first_name","last_name")[0]
        # perms = AdminPermissions.objects.filter(userinfo=pk).values('admin_permissions')[0]
        context = {}
        context.update({'uuid':u.get('uuid')})
        context.update({'email': u.get('email')})
        context.update({'is_active': u.get('is_active')})
        context.update({'first_name': u.get('first_name')})
        context.update({'last_name': u.get('last_name')})

        # context.update({'permissions':perms.get('admin_permissions')})
        return Response(context)

from django.utils.decorators import method_decorator


@method_decorator(csrf_exempt, name='dispatch')

class User_Class(viewsets.ModelViewSet):

    queryset = User.objects.all().order_by('-created_at')
    serializer_class = UserSerializer

    def create(self,request):
        # import pdb;pdb.set_trace()
        if User.objects.filter(email=request.data.get("email")).exists():
            return Response("User with this email already exists, Please use differnt email ID",status=status.HTTP_409_CONFLICT)
    
        
        data = request.data
        ojb = User.objects.count()
        if ojb == 0:
            unique_id = 'F'+ str(1001)
        else:
            last_user = User.objects.all().exclude(is_superuser=True).order_by('-created_at').first()
            if last_user:
                last_user_id = last_user.unique_id
            
                if last_user_id:
                    user_id = int(last_user_id[1:])
                    vara = user_id + 1
                else:
                    vara = 1001
            else:
                vara = 1001
            unique_id = 'F' + str(vara)
        data['unique_id'] = unique_id
        serializer = UserSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            user_data = serializer.data
            user = User.objects.get(email=user_data['email'])
            
            token = RefreshToken.for_user(user).access_token
            

            absurl = f"{request.META['HTTP_ORIGIN']}/user/verify_user/?token={str(token)}"
            
            # email_body = 'Hi '+user.username + \
            
            email_body = 'Hi '+user.first_name + \
                ' Use the link below to verify your email \n' + absurl
            data = {'email_body': email_body, 'to_email': user.email,
                    'email_subject': 'Verify your email'}

            Util.send_email(data)
            return Response(user_data, status=status.HTTP_201_CREATED)

            
        return Response(serializer.errors)

    def list(self,request):
        user = User.objects.all()           
        ser = UserSerializer(user,many=True)
        return Response(ser.data)
    
    def retrieve(self,request,pk):
        
        
        user = User.objects.get(uuid = pk)
        context =[]
        post = UserSerializer(user).data
        role = user.user_role.user_roles if user.user_role else ''
        user.created_at = user.created_at.strftime('%d/%m/%y')            
        if user.last_login:
            user.last_login = user.last_login.strftime('%d/%m/%y , %H:%M')
            post.update({'last_login':user.last_login})
        post.update({
                'created_at':user.created_at,
                'user_role':role
            })
        context.append(post)
    
        return Response(post)

    @action(detail=False, methods=['post'])
    def authorize(self, request):
        # import pdb;pdb.set_trace()
        
        data = request.data
        if User.objects.filter(email=request.data.get('email')).exists():
            user = User.objects.get(email=request.data.get('email'))
            if user:
                if user.check_password(request.data.get('password')):

                    if user.is_verified == True:

                        context = {
                            'results':data,
                            'uuid':user.uuid,
                            'city':user.address,
                            'gender':user.gender,
                            'first_name':user.first_name,
                            'last_name':user.last_name
                            }
                    
                        return Response(context)

                    else:
                        if user.is_verified == False:
                            context = {
                            'results':data,
                            'uuid':user.uuid,
                            'city':user.address,
                            'gender':user.gender,
                            'first_name':user.first_name,
                            'last_name':user.last_name
                            }
                            return Response(context)

                return Response("Password is incorrect", status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response("User does not exist", status=status.HTTP_404_NOT_FOUND)


    @action(detail=False, methods=['post'])
    def social_login(self, request):
        # import pdb;pdb.set_trace()
        
        data = request.data
        if User.objects.filter(social_id=request.data.get('social_id')).exists():
            user = User.objects.get(email=request.data.get('email'))
            if user:
                # if user.check_password(request.data.get('password')):
                context = {
                    'results':data,
                    'uuid':user.uuid,
                    'city':user.address,
                    'gender':user.gender,
                    'first_name':user.first_name,
                    'last_name':user.last_name
                    }
                    # print(request.user)
                return Response(context)
                # return Response("Password is incorrect", status=status.HTTP_401_UNAUTHORIZED)
        else:
            ojb = User.objects.count()
            if ojb == 0:
                unique_id = 'F'+ str(1001)
            else:
                last_user = User.objects.all().exclude(is_superuser=True).order_by('-created_at').first()
                if last_user:
                    last_user_id = last_user.unique_id
                
                    if last_user_id:
                        user_id = int(last_user_id[1:])
                        vara = user_id + 1
                    else:
                        vara = 1001
                else:
                    vara = 1001
                unique_id = 'F' + str(vara)
            data['unique_id'] = unique_id
            dname = data.get('displayName').split()
            context = {
                    'social_id':data.get('social_id'),
                    'email':data.get('email'),
                    'first_name':dname[0],
                    'last_name':dname[1] if len(dname)>1 else '',
                    'unique_id':data.get('unique_id'),
                    'role':'Customer',
                    'phone_number':data.get('mobile',None)
                    }
            serializer = UserSerializer(data=data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors)
        return Response("Something Went Wrong", status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['post'])
    def forgotpassword(self,request):

        serializer = ResetPasswordEmailRequestSerializer(data=request.data)

            # 
        if serializer.is_valid():
            
            user_data = serializer.data
            
            user = User.objects.get(email=user_data['email'])
            
            try:
                
                uidb64 = urlsafe_base64_encode(smart_bytes(user.uuid))

                
                token = PasswordResetTokenGenerator().make_token(user)
                
                absurl = f"{request.META['HTTP_ORIGIN']}/user/ResetConfirm/"+uidb64+"/"+token+"/"
                
                email_body = 'Hi '+user.first_name + \
                    ' Use the link below to reset your password \n' + absurl
                data = {'email_body': email_body, 'to_email': user.email,
                        'email_subject': 'Verify your email'}

                Util.send_email(data)

                
            except Exception as e:
                return Response({'success': 'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)
        
        return Response(serializer.errors)

    @action(detail=False, methods=['get'])
    def ResetConfirm(self, request, uidb64, token):
        
        serializer= SetNewPasswordSerializer(data=request.data)

        try:
            uuid = smart_str(urlsafe_base64_decode(uidb64))
            
            user = User.objects.get(uuid=uuid)

            
            token = request.GET.get("token")

            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error':'Token is not valid, please request a new one'})
            return Response({'success':True,'message':'Credentials Valid','uidb64':uidb64, 'token':token},status=status.HTTP_200_OK)

           

        except DjangoUnicodeDecodeError as identifier:
            # try:
            if not PasswordResetTokenGenerator().check_token(user):
                return Response({'error':'Token is not valid, please request a new one'})

    def partial_update(self, request, *args, **kwargs):
        # import pdb;pdb.set_trace()
        return super().partial_update(request, *args, **kwargs)
    @action(detail=False, methods=['patch'])
    def userupdate(self,request):
        data = request.data
        
        if not User.objects.filter(uuid=data.get('uuid')).exists():
            return Response('Unauthorized')
        user = User.objects.get(uuid=data.get('uuid'))
        ser = UserSerializer(user,data=data,partial=True)
        if ser.is_valid(raise_exception=True):
            
            if AdminPermissions.objects.filter(userinfo=data.get('uuid')).exists():
                perms = AdminPermissions.objects.get(userinfo=data.get('uuid'))
                perms.perm_role = RoleWisePermissions.objects.get(for_role = data.get('user_role'))
                perms.save()

                if Role.objects.get(uuid = data['user_role']).user_roles == 'Instructor':
                    ins = Instructor()
                    ins.instructor_info = User.objects.get(uuid = data.get('uuid'))
                    ins.gym = GymProfile.objects.get(uuid = data.get('gym'))          
                    ins.save()
                
                elif Instructor.objects.filter(gym = data.get('gym'),instructor_info=data.get('uuid')).exists():
                    obj = Instructor.objects.get(gym = data.get('gym'),instructor_info=data.get('uuid'))
                    obj.delete()

            ser.save()
            return Response(('Details saved',ser.data))

        else:
            print(ser.errors)
            return Response(ser.errors)
    
    @action(detail=False, methods=['get'])
    def search_user(self,request):
        data = request.GET
        
        title_contains_query = data.get("first_name")
        search_user = Subscription.objects.filter(gym = data.get('gym'))
        context=[]
        if title_contains_query != " " and title_contains_query is not None:
                search = search_user.filter(subscription_user__first_name__icontains = title_contains_query)
                for i in search:
                    ser = SubscriptionSerializer(i).data
                    user = i.subscription_user.first_name
                    email = i.subscription_user.email
                    unique_id = i.subscription_user.unique_id
                    joined = i.subscription_user.created_at.strftime('%d-%m-%y')
                    civil = i.subscription_user.civil_id
                    user_uuid = i.subscription_user.uuid
                    ser.update({"subscription_user":user,"email":email,"unique_id":unique_id,'joined':joined,'civil_id':civil,'user_uuid':user_uuid})

                    context.append(ser) 

                return Response(context)
        else:
            return Response("User does not exist", status=status.HTTP_404_NOT_FOUND)


    @action(detail=False, methods=['get'])
    def verify_user(self,request):
        
        token = request.GET.get("token")
        
        try:
            
            payload = jwt.decode(jwt=token, key=settings.SECRET_KEY, algorithms=['HS256'])
            
            user = User.objects.get(uuid=payload['uuid'])
            # print(user)
            if not user.is_verified:
                user.is_verified = True
                user.save()
            return Response({'email': 'Successfully activated'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError as identifier:
            return Response({'error': 'Activation Expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError as identifier:
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)


    @action(detail=False, methods=['patch'])
    def setnewpassword(self,request):
        serializer = SetNewPasswordSerializer(request.data)

   
        serializer = serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success': True, 'message': 'Password reset success'}, status=status.HTTP_200_OK)


    @action(detail=False, methods=['post'])
    def logout(self,request):
        serializer = LogoutSerializer(request.data)

    
        # serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(status=status.HTTP_204_NO_CONTENT)



    
class Selected_gym(APIView):
    def get(self,request):
        data = request.GET
        obj = UserSelectedGym.objects.filter(gym_user=data.get('uuid'))
        obj2 = UserSelectedGym.objects.filter(gym_user=data.get('uuid')).values_list('gym')
        uuid_list = [i[0] for i in obj2]
        context=[]
        uuids = []
        for i in obj:
            ser = UserGymSer(i).data
            gym_name = i.gym.gym_name
            theme = i.gym.gym_theme
            gym_initial =  i.gym.gym_name[0]
            ser.update({
                'theme':theme,
                'gym_name':gym_name,
                'gym_initial':gym_initial,
                'uuids':uuid_list
            })
            uuids.extend(uuid_list)
            context.append(ser)
        final_contxt = {'context':context,'uuids':uuids}
        return Response(final_contxt)

    def post(self,request):
        # import pdb;pdb.set_trace()
        data = request.data
        
        if UserSelectedGym.objects.filter(gym_user=data.get('gym_user'),gym=data.get('gym')).exists():
            return Response('Already joined this Gym')
        else:
            ser = UserGymSer(data = data)
            if ser.is_valid(raise_exception=True):
                ser.save()
                return Response(ser.data)
            else:
                return Response(ser.errors)

class SubscribedUserList(APIView):
    def get(self,request):
        data = request.GET
        
        user = Subscription.objects.filter(gym = data.get('gym_id')).distinct('subscription_user')
        
        context =[]
        for value in user:
            x = value.subscription_user
            post = UserSerializer(x).data
            created_at = value.created_at.strftime('%d/%m/%y')            
            if x.last_login:
                last_login = x.last_login.strftime('%d/%m/%y , %H:%M')
                post.update({'last_login':last_login})
                post.update({
                        'created_at':created_at,
                    })
            context.append(post)
        
        return Response(context)
    
class subscription(APIView):
    def get(self,request):
        
        data = request.GET
        if Subscription.objects.filter(subscription_user = data.get("uuid"),gym=data.get('gym_id')).exists():
            value = Subscription.objects.filter(subscription_user = data.get("uuid"),gym=data.get('gym_id')).first()
            print("valueeeeeeeeeeeeeeeee",value)
            res = SubscriptionSerializer(value).data
            print("value passsssssssses",value.passes)
            package = value.package.package_name
            print("ye hai package ",package)

            total_classes_passes = value.package.class_passes
            print("totoal package ",total_classes_passes)
            updated_at =value.updated_at.strftime('%d/%m/%y')
            subscription_validity = value.subscription_validity.strftime('%d %b %Y')
            days = (value.subscription_validity-date.today()).days
            # package_class_passes = UserClass.objects.filter(select_user = data.get("uuid"),gym = data.get('gym_id'))[0].class_passes

            res.update({
                'package':package,
                'updated_at':updated_at,
                'subscription_validity':subscription_validity,
                'package_class_passes':value.passes,
                'days_left':days,
                'total_classes':value.passes
            })
            return Response(res)
        return Response({'package':'No Purchased Package',"updated_at":datetime.today(),"subscription_validity":"","package_class_passes":"0"})

    
    def post(self,request):
        
        data = request.data
        
        if Subscription.objects.filter(subscription_user=data.get('subscription_user'),gym=data.get('gym')).exists():
                user = Subscription.objects.filter(subscription_user=data.get('subscription_user'),gym=data.get('gym')).first()
                                                        
                ser = SubscriptionSerializer(data=data,partial=True)
                # if user.subscription_user.gender == user.gym.gender_criteria or user.gym.gender_criteria =="Unisex" :
                if ser.is_valid(raise_exception=True):
                    if Packages.objects.filter(package_name = data.get("package_id")).exists():#data.get("package_purchased"):
                        ins = UserHistory()
                        
                        ins.action = "Package purchased - " + str(data.get("package_id"))
                        
                        if UserClass.objects.filter(select_user = data.get('subscription_user'),gym=data.get('gym')).exists():
                            subscription_user_passes = UserClass.objects.filter(select_user = data.get('subscription_user'))[0].class_passes

                            
                            ins.package_class_passes = subscription_user_passes + int(data.get("package_class_passes"))
                            
                        else:
                            ins.package_class_passes = data.get("package_class_passes")
                            
                        x = Packages.objects.get(package_name = data.get("package_id"))
                        # print("heyyyyyyyyyyyyyyyyyy")

                        
                        ins.history_price =x.package_price
                        ins.user_detail = user.subscription_user
                        ins.gym = GymProfile.objects.get(uuid = data.get('gym'))
                        ins.save()
# 
                        userclass_detail = UserClass.objects.create(select_user = User.objects.get(uuid = data.get('subscription_user')),class_passes = ins.package_class_passes,gym =GymProfile.objects.get(uuid = data.get('gym')))
                        # print("heyyyyyyyyyyyyyyy")
                        # subscription_detail = Subscription.objects.create(subscription_user = User.objects.get(uuid = data.get('subscription_user')),passes = ins.package_class_passes,gym =GymProfile.objects.get(uuid = data.get('gym')))
                        # print("775dfdsfdsafdsafdsafdsaf",user.subscription_validity)
                        # print("date . todayyyyyyyyyyyy", date.today())
                        if user.subscription_validity >= date.today():
                            
                            subscription_validity = user.subscription_validity + timedelta(weeks=int(x.package_duration))
                            user.subscription_validity=subscription_validity
                            # print('subscription validitydfdfdf',subscription_validity)
                        else:          
                            subscription_validity = date.today() + timedelta(weeks=int(x.package_duration))
                            user.subscription_validity=subscription_validity
                            # print('2222222222222subscription validitydfdfdf',subscription_validity)
                        
                        print("749dfdsfdsafdsafdsafdsaf",user.subscription_validity)
                        user.passes=ins.package_class_passes
                        # print(user.passes)
                        # print("passesssssssssssssssssssssssssss",passes)
                        user.save()
                        # print("7922222222222222222passesssssssssssssssssssssssssss",passes)

                        package = x
                        
                        ser.validated_data.update({
                            'subscription_status':True,
                            'fee_status':'Paid',
                            'subscription_validity':subscription_validity,
                            'passes':ins.package_class_passes,
                            'package':package,
                            'gym':GymProfile.objects.get(uuid = data.get('gym')),
                            
                        })
                        
                        ser.save()
                        
                        return Response(ser.data)

                    


                    
                #     else:
                #         ins = UserHistory()
                        
                #         x = Membership.objects.get(membership_title = data.get("membership"))
                #         ins.action = "Membership purchased - " + str(x.membership_title)

                #         ins.package_class_passes =int(UserClass.objects.filter(select_user = data.get('subscription_user'))[0].class_passes)
                #         #  + int(x.membership_description)
                #         ins.package_expiry = date.today() + timedelta(weeks=int(x.membership_duration))
                #         ins.user_detail = user.subscription_user
                #         ins.history_price = x.membership_amount
                #         ins.gym = GymProfile.objects.get(uuid = data.get('gym'))
                #         ins.save()

                #         ser.validated_data.update({
                #             'subscription_status':True,
                #             'fee_status':'Paid',
                #             'membership_validity':ins.package_expiry,
                #             'membership_purchased':x,
                #             'gym':GymProfile.objects.get(uuid = data.get('gym')),
                            
                #         })
                #         ser.save()
                #         return Response(ser.data)

                # return Response(ser.errors)
            # else:
            #     return Response("Gender Criteria for this gym Doesn't satisfy with yours",status=status.HTTP_406_NOT_ACCEPTABLE) 
                 
        else:
            res_serializer = SubscriptionSerializer(data = data)
            user = User.objects.get(uuid = data.get('subscription_user'))
            gym = GymProfile.objects.get(uuid = data.get('gym'))
            
            # if user.gender == gym.gender_criteria or gym.gender_criteria == 'Unisex':
            if res_serializer.is_valid():
                if data.get('package_id'):
                    ins = UserHistory()
                    ins.action = "Package purchased - " + data.get("package_id")
                    
                    # if UserClass.objects.filter(select_user = data.get('subscription_user'),gym=data.get('gym')).exists():
                    #     passes = UserClass.objects.filter(select_user = data.get('subscription_user'))[0].class_passes
                    #     ins.package_class_passes = int(passes) + int(data.get("package_class_passes"))
                    # else:
                    #     ins.package_class_passes = data.get("package_class_passes")

                    x = Packages.objects.filter(package_name = data.get("package_id"))[0]
                    class_passes=x.class_passes
                    print("cpppppppppppppppppppppppppppppp",class_passes)
                    # ins.package_expiry = datetime.now() + timedelta(weeks=int(x.package_duration))
                    ins.user_detail = User.objects.get(uuid = data.get('subscription_user'))
                    ins.history_price = x.package_price
                    ins.gym = GymProfile.objects.get(uuid = data.get('gym'))
                    ins.save()

                    userclass_passes = UserClass.objects.create(select_user = User.objects.get(uuid = data.get('subscription_user')),class_passes = class_passes,gym =GymProfile.objects.get(uuid = data.get('gym')))

                    subscription_status = True
                    fee_status = "Paid"
                    subscription_validity = date.today()+ timedelta(weeks=int(x.package_duration))
                    package = x
                    gym = GymProfile.objects.get(uuid = data.get('gym'))
                    res_serializer.validated_data.update({
                            'subscription_status':subscription_status,
                            'fee_status':fee_status,
                            'subscription_validity':subscription_validity,
                            'package':package,
                            'gym':gym,
                            'passes':class_passes
                            
                        })

                    res_serializer.save()
                # else:
                #     ins = UserHistory()
                #     x = Membership.objects.filter(membership_title = data.get("membership"))[0]
                #     ins.action = "Membership purchased - " + data.get("membership")
                    
                #     membership_validity = date.today() + timedelta(weeks=int(x.membership_duration))


                #     ins.history_price = x.membership_amount
                #     ins.user_detail = user
                #     # .subscription_user
                #     ins.gym = GymProfile.objects.get(uuid = data.get('gym'))
                #     # package = Packages.objects.filter(package_name = data.get('package_id'))[0]
                #     # print("packageeeeeeeeeee",package)
                #     # subscription_validity = date.today() + timedelta(weeks=int(package.package_duration))
                #     # passes=package.class_passes
                #     ins.save()

                #     res_serializer.validated_data.update({
                #         'subscription_status':True,
                #         'fee_status':'Paid',
                #         'membership_validity':membership_validity,
                #         # 'subscription_validity':subscription_validity,
                #         'membership_purchased':x,
                #         # 'package':package,
                #         # 'passes':passes,
                #         'gym':GymProfile.objects.get(uuid = data.get('gym'))
                    
                        
                #     })
                #     res_serializer.save()
                    return Response(res_serializer.data)
                return Response(res_serializer.errors)
            # else:
            #     raise Http404("Gender Criteria for this gym Doesn't satisfy with yours") 

class UserHistoryDetail(APIView):
    def get(self,request,pk):
        # import pdb;pdb.set_trace()
        if UserHistory.objects.filter(user_detail = pk).exists():
            
            data = request.GET
            query = UserHistory.objects.filter(user_detail = pk,gym = data.get('gym_id')).order_by('-created_at')
            context=[]
            output={}
            for value in query:
                serializer =  UserHistorySerializer(value).data
                created_at = value.created_at.strftime('%d %b %Y')
                created_time =  value.created_at.time().strftime('%H:%M')
                serializer.update({
                    'created_at':created_at,
                    'created_time':created_time
                })
                if output.get(created_at):
                    output[created_at].append(serializer)
                else:
                    output[created_at]=[serializer]
            for i in output:
                context.append({'date':i,'data':output[i]})
            # context = sorted(context,key=lambda x:x['date'],reverse=True)
            return Response(context)
        return Response(request.data)


    def delete(self, request, pk, format=None):
        admin = self.get_object(pk)
        admin.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# def classes():
#     inner_qs = UserClass.objects.values_list('select_classes',flat=True)
#     print("kjhgkjhkjhkjhkjh",inner_qs)
        #  results = table1.objects.exclude(field1__in=inner_qs)

class BookClass(APIView):
    def get(self,request):

        try:
        
            data = request.GET

            from django.db import connection
            cursor = connection.cursor()
            cursor.execute('''SELECT DISTINCT gymprofile_classes.basemodel_ptr_id,class_topic, class_price, select_user_id, select_classes_id, booked_day, is_booked FROM user_userclass FULL OUTER JOIN gymprofile_classes ON user_userclass.select_classes_id = gymprofile_classes.basemodel_ptr_id''')
            # row = cursor.fetchone()
            # print("rowwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww",row)

            rowall = cursor.fetchall()
            

            s=[{"class_uuid": rall[0], "class_topic": rall[1], "class_price":rall[2], "select_user_id":rall[3], "select_classes_id":rall[4], "booked_day":rall[5], "is_booked":rall[6]} for rall in rowall]
            print("sssssssssssssssssssssssssssssssssss",s)
           
               
            my_date = date.today()
            current_day=calendar.day_name[my_date.weekday()]

            return Response(s)
        except Exception as e:
            return Response('book class not Found')
    
    
    def post(self,request):
        
        data = request.data
        if UserClass.objects.filter(select_user=data.get('user_uuid'),gym = data.get('gym_id')).exists():

            user = UserClass.objects.filter(select_user=data.get('user_uuid'),gym = data.get('gym_id'))[0]
            select_user = user.select_user
            value = Subscription.objects.filter(subscription_user = data.get("user_uuid"),gym=data.get('gym_id'))[0]
            # value.passes=int(value.passes)-1
            print("iffffffffffffffffffffffffffffffffffffff")
            class_passes  = value.passes
            # value.save()
            if class_passes >= 0:
                classes = Classes.objects.get(uuid = data.get("class_uuid"))
                gym = GymProfile.objects.get(uuid =data.get("gym_id"))
                date = data.get('date')
                booked_date = datetime.strptime(date,'%d %b %Y')
                booked_day=booked_date.strftime('%A')


                if UserClass.objects.filter(select_classes = data.get('class_uuid'),booked_date=booked_date,booked_day = booked_day,select_user=data.get('user_uuid'),gym = data.get('gym_id')).exists():
                    
                    book_status=user.is_booked
                    # print("bookstatusssssssssssssss",book_status)
                    context={
                        # 'gym':gym,
                        # 'select_user':select_user,
                        # 'class_passes':class_passes,
                        # 'select_classes':classes,
                        'booked_date': booked_date.date(),
                        'booked_day':booked_day,
                        'is_booked':book_status
                        
                    }
                    
                    return Response(context,status=status.HTTP_208_ALREADY_REPORTED )
    

                    # return Response('User already booked class' ,status=status.HTTP_208_ALREADY_REPORTED )
                    

                else:
                    print("elseeeeeeeeeeeeeeeeeeeee")
                    value.is_booked=True
                    user.is_booked=True
                    user.booked_day=booked_day
                    
                    value.passes=int(value.passes)-1
                    class_passes  = value.passes
                    value.save()
                    book_status=value.is_booked
                    user1 = UserClass.objects.create(select_user=User.objects.get(uuid = data.get('user_uuid')),is_booked=book_status,booked_day=booked_day,class_passes = class_passes,gym =GymProfile.objects.get(uuid = data.get('gym_id')))
                    # user1 = UserClass.objects.create(select_user = User.objects.get(uuid = data.get('subscription_user')),class_passes = ins.package_class_passes,gym =GymProfile.objects.get(uuid = data.get('gym')))
                            
                    user.seat_available = int(classes.no_of_participants) - 1
                    seat_available=user.seat_available
                    print("seat availableeeeeeeeeeeeeeeeeeeeeee",seat_available)
                if seat_available > 0:
                    
                    context={
                        'gym':gym,
                        'select_user':select_user,
                        'class_passes':class_passes,
                        'select_classes':classes,
                        'booked_date': booked_date.date(),
                        'booked_day':booked_day,
                        'is_booked':book_status,
                        'seat_available' : seat_available
                    }

                    res_serializer = UserclassSerializer(data = context)
                    if res_serializer.is_valid():
                        
                        history = UserHistory()
                        history.user_detail = User.objects.get(uuid = data.get('user_uuid'))
                        history.action = 'class booked - ' + classes.class_topic + ' for '+data.get('date')
                        history.package_class_passes = class_passes
                        history.type = 'Schedule'
                        history.history_price = classes.class_price
                        history.history_image = classes.class_image
                        history.for_date = booked_date.date()
                        
                        history.gym = GymProfile.objects.get(uuid =data.get('gym_id'))
                        history.is_booked=True

                        history.save()
                        res_serializer.save()
                        # history.class_booked_date = 
                        return Response(res_serializer.data)
                    
                    return Response(res_serializer.errors)
                
                return Response('Seats not available for this class')

            classes = Classes.objects.get(uuid = data.get("class_uuid"))
            print("classesssssssssssssssssssssss",classes)
            gym = GymProfile.objects.get(uuid =data.get("gym_id"))
            print("gymmmmmmmmmmmmmmmmmmm",gym)
            date = data.get('date')
            print("dateeeeeeeeeeeeeeeeeeeeeee",date)
            booked_date = datetime.strptime(date,'%d %b %Y')
            booked_day=booked_date.strftime('%A')
            user.is_booked=False
            print("userisbookeddddddddddddd",user.is_booked)
            user.save()
            
            book_status=user.is_booked
            con={
                        'gym':gym,
                        'select_user':select_user,
                        'class_passes':class_passes,
                        'select_classes':classes,
                        'booked_date': booked_date.date(),
                        'booked_day':booked_day,
                        'is_booked':book_status
                        
                    }

                
            return Response(con,status=status.HTTP_404_NOT_FOUND)
        else:
            try:
                user = UserClass()
                value = Subscription.objects.filter(subscription_user = data.get("user_uuid"),gym=data.get('gym_id')).first()
                # value.package.class_passes=str(int(value.package.class_passes)-1)
                value.is_booked=True
                
                value.passes=int(value.passes)-1
                value.save()
                user.class_passes=int(value.passes)
                user.select_user = User.objects.get(uuid=data.get('user_uuid'))
                user.gym = GymProfile.objects.get(uuid=data.get('gym_id'))
                user.is_booked=True
                date = data.get('date')
                classes = Classes.objects.get(uuid = data.get("class_uuid"))
                user.select_classes = classes
                user.booked_date = datetime.strptime(date,'%d %b %Y').date()
                user.booked_day=user.booked_date.strftime('%A')
                user.seat_available = int(classes.no_of_participants) - 1
                user.save()
                history = UserHistory()
                history.user_detail = User.objects.get(uuid = data.get('user_uuid'))
                history.action = 'class booked - ' + classes.class_topic + ' for '+data.get('date')
                history.package_class_passes = int(value.passes)
                history.is_booked=True
                history.type = 'Schedule'
                history.history_price = classes.class_price
                history.for_date = datetime.strptime(date,'%d %b %Y').date()
                history.history_image = classes.class_image
                history.gym = GymProfile.objects.get(uuid =data.get('gym_id'))
                history.save()
                return Response(UserclassSerializer(user).data)
            except Exception as e:
                
                return Response({'message':str(e)})




   

class Bookings(APIView):
    def get(self,request):
        
        data = request.GET
        obj = UserClass.objects.filter(select_classes=data.get('class'),gym=data.get('gym'))
        context = []
        for v in obj:
            if v.booked_date:
                ser = UserclassSerializer(v).data
                user = v.select_user.first_name
                ser.update({
                    'select_user':user
                })
                context.append(ser)
        return Response(context)

class UpcomingBookClass(APIView):
    def get(self,request):
        
        data = request.GET
        query = UserClass.objects.filter(select_user = data.get("uuid"),booked_date__gte=date.today(),gym = data.get('gym_id')).order_by('created_at')
        context = []
        for value in query:
            if value.booked_date:
                if value.select_classes and value.gym and value.booked_date > date.today() :
                    serializer =  UserclassSerializer(value).data
                    created_at = value.created_at.strftime('%d/%m/%y')
                    class_obj = value.select_classes.class_topic
                    st_t = value.select_classes.start_time.strftime('%H:%M')
                    dur = int(value.select_classes.end_time.strftime('%H')) - int(value.select_classes.start_time.strftime('%H'))
                    booked_date = value.booked_date.strftime('%d %b %Y')
                    serializer.update({
                        'created_at':created_at,
                        'select_classes':class_obj,
                        'booked_date':booked_date,
                        'start_time':st_t,
                        'duration':dur

                    })
                    context.append(serializer)
        return Response(context)


def user_data_async(request):
    
    users = list(
        Subscription.objects.filter().values('subscription_user__uuid', 'updated_at', 'subscription_user__first_name','subscription_user__last_name', 'created_at', 'subscription_user__email', 'subscription_user__phone_number', 'subscription_user__gender', 'subscription_user__dob','subscription_user__civil_id','subscription_user__address', 'subscription_user__user_role__user_roles','subscription_user__unique_id','subscription_user__username','subscription_user__last_login').order_by('-created_at'))

    for i in users:
        i['created_at_time'] = i['created_at'].strftime('%H:%M:%S')
        i['created_at'] = i['created_at'].strftime("%d-%m-%Y")
        try:
            i['last_login_at_time'] = i['last_login'].strftime('%H:%M:%S')
            i['last_login_at'] = i['last_login'].strftime("%d-%m-%Y")
            i['last_active_days'] = (datetime.now(timezone.utc) - i['last_login']).days
        except Exception as e:
            print(str(e))
            i['last_login_at_time'] = None
            i['last_login_at'] = None
            i['last_active_days'] = None
            pass
    
    users = pd.DataFrame(users)
    users = users.to_csv('media/userdata.csv')
    url = 'http://127.0.0.1:8000/media/userdata.csv'
    return url


# *************Course***************

class BookCourse(APIView):
    def get(self,request):
        try:
        
            data = request.GET
            query = UserCourse.objects.filter(select_user = data.get("uuid"),gym = data.get('gym_id')).order_by('-created_at')
            context = []
            for value in query:
                # if value.booked_date:
                if value.select_courses and value.gym:
                    serializer =  UsercourseSerializer(value).data
                    created_at = value.created_at.strftime('%d/%m/%y')
                    class_obj = value.select_courses.course_name
                    st_t = value.select_courses.start_time.strftime('%H:%M')
                    ed_t = value.select_courses.end_time
                    dur = int(value.select_courses.end_time.strftime('%H')) - int(value.select_courses.start_time.strftime('%H'))
                    # booked_date = value.booked_date.strftime('%d %b %Y')
                    serializer.update({
                        'created_at':created_at,
                        'select_course':class_obj,
                        'is_booked':value.is_booked,
                        'start_time':st_t,
                        'duration':dur
                    })
                    context.append(serializer)
            return Response(context)
        except Exception as e:
            return Response('data not found')

    
    def post(self,request):
        
        data = request.data
        
            
        if UserCourse.objects.filter(select_user=data.get('select_user'),gym = data.get('gym')).exists():

            user = UserCourse.objects.filter(select_user=data.get('select_user'),gym = data.get('gym'))[0]
            select_user = user.select_user
            #value = Subscription.objects.filter(subscription_user = data.get("user_uuid"),gym=data.get('gym_id'))[0]
            # value.passes=int(value.passes)-1
            
            # value.save()
           
            courses = Course.objects.get(uuid = data.get("select_courses"))
            gym = GymProfile.objects.get(uuid =data.get("gym"))
            date = data.get('date')
            booked_date = datetime.strptime(date,'%d %b %Y')

            if UserCourse.objects.filter(select_courses = data.get('select_courses'),booked_date = booked_date,select_user=data.get('select_user'),gym = data.get('gym')).exists():
                book_status=user.is_booked
                    # print("bookstatusssssssssssssss",book_status)
                context = {'is_booked':book_status}
                return Response(context,status=status.HTTP_208_ALREADY_REPORTED )

                # return Response('User already booked course' ,status=status.HTTP_208_ALREADY_REPORTED )
                
            else:
                
                course_obj = courses
                user.is_booked=True
                book_status=user.is_booked
                user.save()
                seat_available = int(courses.no_of_participants) - 1
                
            if seat_available > 0:
                
                context={
                    'gym':gym,
                    'select_user':select_user,
                    'select_courses':course_obj,
                    'is_booked':book_status,

                    'booked_date': booked_date.date(),
                    'seat_available' : seat_available
                }

        
                res_serializer = UsercourseSerializer(data = context)
                if res_serializer.is_valid():
                    
                    history = UserHistory()
                    history.user_detail = User.objects.get(uuid = data.get('select_user'))
                    history.action = 'course booked - ' + courses.course_name + ' for '+data.get('date')
                    
                    history.is_booked=True
                    history.type = 'Schedule'
                    history.history_price = courses.course_price
                    history.history_image = courses.course_image
                    history.for_date = booked_date.date()
                    history.gym = GymProfile.objects.get(uuid =data.get('gym'))
                    history.save()
                    res_serializer.save()
                    # history.class_booked_date = 
                    return Response(res_serializer.data,status=status.HTTP_200_OK)

        # if user with same gym_id does not exist

        course = Course.objects.get(uuid=data.get('select_courses'))
        date = data.get('date')
        booked_date = datetime.strptime(date,'%d %b %Y')

        seats = (int(course.seat_available)-1)
        # 
        if seats>=0:
            ser = UsercourseSerializer(data=data)
            if ser.is_valid():
                ser.save()
                course.seat_available =(int(course.seat_available)-1)
                print("5222222222222222222")
                course.save()
                history = UserHistory()
                history.is_booked=True
                history.user_detail = User.objects.get(uuid = data.get('select_user'))
                history.action = 'Course booked - ' + course.course_name + ' from '+str(course.course_start_date)+' to '+str(course.course_end_date)
               
                    
                # history.package_class_passes = int(value.passes)
                history.type = 'Schedule'
                print()
                history.history_price = course.course_price
                history.for_date = booked_date.date()
                history.history_image = course.course_image
                history.gym = GymProfile.objects.get(uuid =data.get('gym'))
                history.save()
                return Response(ser.data)
            else:
                return Response(ser.errors)
        
            # return Response('Seats not available for this course')
        
    
    
class CourseBookings(APIView):
    def get(self,request):
        
        data = request.GET
        obj = UserClass.objects.filter(select_courses=data.get('class'),gym=data.get('gym'))
        context = []
        for v in obj:
            if v.booked_date:
                ser = UsercourseSerializer(v).data
                user = v.select_user.first_name
                ser.update({
                    'select_user':user
                })
                context.append(ser)
        return Response(context)


class UpcomingBookCourse(APIView):
    def get(self,request):
        
        data = request.GET
        query = UserCourse.objects.filter(select_user = data.get("uuid"),gym = data.get('gym_id')).order_by('created_at')
        context = []
        for value in query:
            if value.booked_date:
                if value.select_courses and value.gym and value.booked_date > date.today() :
                    serializer =  UserclassSerializer(value).data
                    created_at = value.created_at.strftime('%d/%m/%y')
                    class_obj = value.select_courses.class_topic
                    st_t = value.select_courses.start_time.strftime('%H:%M')
                    dur = int(value.select_courses.end_time.strftime('%H')) - int(value.select_courses.start_time.strftime('%H'))
                    booked_date = value.booked_date.strftime('%d %b %Y')
                    serializer.update({
                        'created_at':created_at,
                        'select_courses':class_obj,
                        'booked_date':booked_date,
                        'start_time':st_t,
                        'duration':dur

                    })
                    context.append(serializer)
        return Response(context)

# *******************************************************************


def get_gym_data(gym_id):
    value = GymProfile.objects.get(uuid=gym_id)
    post = GymProfileSerializer(value).data
    age = value.age_criteria.name
    time = value.gym_timings.time_text
    location = value.city.all()
    loactionlist=[]
    for i in location:
        location = i.gym_location
        loactionlist.append(location)
    days= value.opening_days.all()
    context=[]
    for i in days:
        day = i.day
        context.append(day)
    post.update({
        'age_criteria':age,
        'gym_timings':time,
        'opening_days':context,
        'city':loactionlist
    })
    return post


def get_class_list(user_id,gym_id):
    query = UserClass.objects.filter(select_user = user_id,booked_date__gte=date.today(),gym = gym_id).order_by('booked_date')
    context = []
    classes=[]
    for value in query:        
        serializer =  UserclassSerializer(value).data
        created_at = value.created_at.strftime('%d/%m/%y')
        class_obj = value.select_classes.class_topic
        st_t = value.select_classes.start_time.strftime('%H:%M')
        dur = int(value.select_classes.end_time.strftime('%H')) - int(value.select_classes.start_time.strftime('%H'))
        booked_date = value.booked_date.strftime('%d %b %Y')
        serializer.update({
            'created_at':created_at,
            'select_classes__uuid':value.select_classes.uuid,
            'select_classes':class_obj,
            'booked_date':booked_date,
            'start_time':st_t,
            'duration':dur

        })
        if value.booked_date == date.today() :
            classes.append(serializer)
        else:
            context.append(serializer)
    return context,classes

def get_history(user_id,gym_id):
    # import pdb;pdb.set_trace()
    if UserHistory.objects.filter(user_detail=user_id).exists():
        query = UserHistory.objects.filter(user_detail = user_id,gym = gym_id).order_by('-created_at')[:4]
        context=[]
        for value in query:
            serializer =  UserHistorySerializer(value).data
            created_at = value.created_at.strftime('%d/%m/%Y')
            created_time =  value.created_at.time().strftime('%H:%M')
            serializer.update({
                'created_at':created_at,
                'created_time':created_time
            })
            context.append(serializer)
        return context
    return []


def get_Subscription(user_id,gym_id):
    # data = request.GET
    if Subscription.objects.filter(subscription_user = user_id,gym=gym_id).exists():
        value = Subscription.objects.filter(subscription_user = user_id,gym=gym_id)[0]
        res = SubscriptionSerializer(value).data
        package = value.package.package_name
        total_classes = value.package.class_passes
        updated_at =value.updated_at.strftime('%d/%m/%y')
        subscription_validity = value.subscription_validity.strftime('%d %b %Y')
        days = (value.subscription_validity-date.today()).days
        package_class_passes = UserClass.objects.filter(select_user = user_id,gym=gym_id)[0].class_passes

        res.update({
            'package':package,
            'updated_at':updated_at,
            'subscription_validity':subscription_validity,
            'package_class_passes':package_class_passes,
            'days_left':days,
            'total_classes':total_classes
        })
        return res
    return {'package':'No Purchased Package',"updated_at":datetime.today(),"subscription_validity":"","package_class_passes":"0"}
class UserProfile(APIView):
    def get(self,request):
        try:
            gym_id = request.GET.get('gym_id')
            user_id = request.GET.get('uuid')
            gym_data = get_gym_data(gym_id)
            upcoming,current = get_class_list(user_id,gym_id)
            histories = get_history(user_id,gym_id)
            subs = get_Subscription(user_id,gym_id)
            context = {
                "gym_data":gym_data,
                "class_data":upcoming,
                'current':current,
                "histories":histories,
                "subs":subs
            }
            return Response(context)
        except Exception as e:
            return Response('user profile not Found')

        


def getGroupedSchedules(user_id,gym_id):
    query = UserClass.objects.filter(select_user = user_id,booked_date__gte=date.today(),gym = gym_id).order_by('booked_date')
    context = []
    output={}
    for value in query:        
        serializer =  UserclassSerializer(value).data
        created_at = value.created_at.strftime('%d/%m/%y')
        class_obj = value.select_classes.class_topic
        st_t = value.select_classes.start_time.strftime('%H:%M')
        dur = int(value.select_classes.end_time.strftime('%H')) - int(value.select_classes.start_time.strftime('%H'))
        booked_date = value.booked_date.strftime('%d %b %Y')
        serializer.update({
            'created_at':created_at,
            'select_classes_uuid':value.select_classes.uuid,
            'select_classes':class_obj,
            'booked_date':booked_date,
            'start_time':st_t,
            'duration':dur,
            'history_image':value.select_classes.class_image.url,
            'description':value.select_classes.class_description,
            'price':value.select_classes.class_price
        })
        if output.get(booked_date):
            output[booked_date].append(serializer)
        else:
            output[booked_date]=[serializer]
    for i in output:
        context.append({'date':i,'data':output[i]})
    context = sorted(context,key=lambda x:x['date'])
    return context

class GetSchedules(APIView):
    def get(self,request):
        try:
            user_id = request.GET.get('uuid')
            gym_id = request.GET.get('gym_id')
            schedule = getGroupedSchedules(user_id,gym_id)
            return Response({'schedule':schedule})
        except Exception as e:
            return Response('scheduled not Found')



def getCoursesSchedules(user_id,gym_id):
    query = UserCourse.objects.filter(select_user = user_id,gym = gym_id).order_by('select_courses__course_start_date')
    context = []
    output={}
    for value in query:
        if value.select_courses.course_start_date.month>=date.today().month:
            serializer =  UsercourseSerializer(value).data
            created_at = value.created_at.strftime('%d/%m/%y')
            course_obj = value.select_courses.course_name
            st_t = value.select_courses.start_time.strftime('%H:%M')
            dur = value.select_courses.course_end_date - value.select_courses.course_start_date
            start_date = value.select_courses.course_start_date.strftime('%d %b %Y')
            end_date = value.select_courses.course_end_date.strftime('%d %b %Y')
            serializer.update({
                'created_at':created_at,
                'select_classes':course_obj,
                'start_date':start_date,
                'end_date':end_date,
                'start_time':st_t,
                'duration':dur.days,
                'history_image':value.select_courses.course_image.url,
                # 'description':value.select_classes.class_description,
                'price':value.select_courses.course_price
            })
            if output.get(start_date):
                output[start_date].append(serializer)
            else:
                output[start_date]=[serializer]
    for i in output:
        context.append({'date':i,'data':output[i]})
    context = sorted(context,key=lambda x:x['date'])
    return context

class GetCourseSchedules(APIView):
    def get(self,request):
        try:
            user_id = request.GET.get('uuid')
            gym_id = request.GET.get('gym_id')
            schedule = getCoursesSchedules(user_id,gym_id)
            return Response({'schedule':schedule})

        except Exception as e:
            return Response('course schedule not Found')

# def fillCourses():
#     courses = Course.objects.all()
#     for course in courses:
#         course.seat_available = 20
#         course.save()
#         print('Course Name : '+str(course.course_name))
#     print('Finished')

# fillCourses()

class CancelClass(APIView):
    def post(self,request):
        # import pdb;pdb.set_trace()
        data = request.data
        booked_date = datetime.strptime(data.get('date'),'%d %b %Y').date()
        if UserClass.objects.filter(select_user=data.get('user_uuid'),select_classes=data.get('class_uuid'),gym = data.get('gym_id'),booked_date=booked_date).exists():
            uc_instance =UserClass.objects.filter(select_user=data.get('user_uuid'),select_classes=data.get('class_uuid'),gym = data.get('gym_id'),booked_date=booked_date).first()
            uc_instance.delete()
            value = Subscription.objects.filter(subscription_user = data.get("user_uuid"),gym=data.get('gym_id')).first()
                
            value.passes=int(value.passes)+1
            value.save()
            classes = Classes.objects.get(uuid = data.get("class_uuid"))
            history = UserHistory()
            history.user_detail = User.objects.get(uuid = data.get('user_uuid'))
            history.action = 'class canceled - ' + classes.class_topic + ' for '+data.get('date')
            history.package_class_passes = int(value.passes)
            # history.type = 'Schedule'
            history.history_price = classes.class_price
            # history.for_date = datetime.strptime(date,'%d %b %Y').date()
            history.history_image = classes.class_image
            history.gym = GymProfile.objects.get(uuid =data.get('gym_id'))
            history.save()
            # classes = Classes.objects.get(uuid = data.get("class_uuid"))
            return Response('Class Canceled')
        return Response('No Class Found')


class CancelCourse(APIView):
    def post(self,request):
        # import pdb;pdb.set_trace()
        data = request.data
        # booked_date = datetime.strptime(data.get('date'),'%d %b %Y').date()
        if UserCourse.objects.filter(select_user=data.get('user_uuid'),select_courses=data.get('course_uuid'),gym = data.get('gym_id')).exists():
            print(UserCourse.objects.filter(select_user=data.get('user_uuid'),select_courses=data.get('course_uuid'),gym = data.get('gym_id')).count())
            uc_instance =UserCourse.objects.filter(select_user=data.get('user_uuid'),select_courses=data.get('course_uuid'),gym = data.get('gym_id')).first()
            uc_instance.delete()
            # value = Subscription.objects.filter(subscription_user = data.get("user_uuid"),gym=data.get('gym_id')).first()
                
            # value.passes=int(value.passes)+1
            # value.save()
            classes = Course.objects.get(uuid = data.get("course_uuid"))
            history = UserHistory()
            history.user_detail = User.objects.get(uuid = data.get('user_uuid'))
            history.action = 'Course canceled - ' + classes.course_name + ' starting from '+datetime.strftime(classes.course_start_date,'%d %b %Y')
            history.package_class_passes = int(value.passes)
            history.type = 'Schedule'
            history.history_price = classes.course_price
            history.for_date = datetime.strptime(date,'%d %b %Y').date()
            history.history_image = classes.course_image
            history.gym = GymProfile.objects.get(uuid =data.get('gym_id'))
            history.save()
            # classes = Classes.objects.get(uuid = data.get("class_uuid"))
            return Response('Course Canceled')
        return Response('No such Course Found')
# 


