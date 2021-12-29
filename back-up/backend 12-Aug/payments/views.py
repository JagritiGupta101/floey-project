# from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework import viewsets,status
from .models import *
from .serializers import *
from rest_framework.response import Response
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from user.models import *
from user.serializers import *
# from rest_framework.authentication import SessionAuthentication, BasicAuthentication 
import pandas as pd
import os
import csv
from django.conf import settings
from django.utils.text import slugify
from decimal import Decimal



# Create your views here.


# class CsrfExemptSessionAuthentication(SessionAuthentication):

#     def enforce_csrf(self, request):
#         return 

class GymRuleAPI(viewsets.ModelViewSet):
    queryset = GymRule.objects.all()
    serializer_class = GymRuleSerializer

    def list(self,request):
        data = self.queryset
        context =[]
        for i in data:
            ser = GymRuleSerializer(i).data
            gyms = i.gyms.all()
            lst=[]
            for val in gyms:
                name = val.gym_name
                lst.append(name)
            ser.update({
                'gyms':lst
            })
            context.append(ser)
        
        return Response(context)

    def create(self,request):
        # 
        data = request.data
        ser = GymRuleSerializer(data=data)
        if ser.is_valid():
            ser.save()
            return Response(ser.data)
        return Response(ser.errors)

class MaxUses(viewsets.ModelViewSet):
    queryset = MaxUsageRule.objects.all()
    serializer_class = MaxUsesSerializer


class CouponUsersList(viewsets.ModelViewSet):
    queryset = CouponUser.objects.all()
    serializer_class = CouponUserSerializer


class Rulesets(viewsets.ModelViewSet):
    queryset = Ruleset.objects.all()
    serializer_class = RulesetSerializer

    def list(self,request):
        query = self.queryset
        context=[]
        for i in query:
            # 
            ser = RulesetSerializer(i).data
            # all_gyms = i.gyms_ruleset.all_gyms
            gymruleset = i.gyms_ruleset.gyms.all()
            lst=[]
            for val in gymruleset:
                gym = val.gym_name
                lst.append(gym)
            usage = i.max_uses_rule.max_usage_per_user
            print(lst)
            ser.update({
                'gyms_ruleset':lst,
                'max_uses_rule':usage,
                # 'all_gyms':all_gyms
            })
            context.append(ser)
        return Response(context)

    def create(self,request):
        # 
        data  = request.data
        ser = RulesetSerializer(data = data)
        if ser.is_valid():
            ser.save()
            return Response(ser.data)
        print(ser.errors)
        return Response(ser.errors)


class Promo(viewsets.ModelViewSet):
    queryset = PromoCode.objects.all()
    serializer_class = PromocodeSerializer


class OfferDetails(APIView):
    def get_object(self, offerid):
        try:
            return PromoCode.objects.get(uuid=offerid)
        except Offers.DoesNotExist:
            raise Http404

    def get(self, request, offerid):
        offer = self.get_object(offerid)
        serializer = OfferSerializer(offer, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, offerid):
        data = request.data
        offer = self.get_object(offerid)
        serializer = OfferSerializer(offer, data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, offerid):
        offer = self.get_object(offerid)
        offer.delete()
        return Response({'message': 'Banner deleted'}, status=status.HTTP_204_NO_CONTENT)   


def validate_allowed_users_rule(coupon_object, user):
    allowed_users_rule = coupon_object.ruleset_id.max_uses_rule
    if not user in allowed_users_rule.allowed_user.all():
        return False if not allowed_users_rule.all_users else True

    return True


def validate_max_uses_rule(coupon_object, user):
    max_uses_rule = coupon_object.ruleset_id.max_uses_rule
    if coupon_object.max_usage >= max_uses_rule.max_usage_per_user :
        return False

    try:
        coupon_user = CouponUser.objects.get(coupon_user=user)
        if coupon_user.usage_count >= max_uses_rule.max_usage_per_user:
            return False
    except CouponUser.DoesNotExist:
        pass

    return True


def validate_validity_rule(coupon_object):
    validity_rule = coupon_object.end_date
    if timezone.now().date() > validity_rule:
        return False
    return True
    # return coupon_object.active_status

def validate_allowed_gyms_rule(coupon_object,gym):
    rule = coupon_object.ruleset.gyms_ruleset
    if not rule.gyms.filter(uuid=gym).exists():
        return False if not rule.all_gyms else True
    return True

# @csrf_exempt
class ApplyPromocode(APIView):
    # authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication)

    def get(self,request):
        query = PromoCode.objects.all()
        ser = PromocodeSerializer(query,many = True)
        return Response(ser.data)

    def post(self,request):
        
        if not User.objects.filter(uuid = request.data.get('uuid')).exists():
            return Response({"message":"User Not Found"})
        user = User.objects.get(uuid =request.data.get('uuid'))
        coupon_code = request.data.get('coupon_code')
        gym = request.data.get('gym')
        
        if not coupon_code:
            return Response({"status":False, "message":"No coupon code provided!"},status=status.HTTP_406_NOT_ACCEPTABLE)

        try:
            coupon_object = PromoCode.objects.get(code=coupon_code)
        except Offers.DoesNotExist:
            return Response({"status":False, "message": "Coupon does not exist!"},status=status.HTTP_406_NOT_ACCEPTABLE)

        valid_allowed_users_rule = validate_allowed_users_rule(coupon_object=coupon_object, user=user)
        if not valid_allowed_users_rule:
            return Response({"status":False, "message": "Invalid coupon for this user!"},status=status.HTTP_406_NOT_ACCEPTABLE)
        
        valid_max_uses_rule = validate_max_uses_rule(coupon_object=coupon_object, user=user)
        if not valid_max_uses_rule:
            return Response({"status":False, "message": "Coupon uses exceeded for this user!"},status=status.HTTP_406_NOT_ACCEPTABLE)

        try:
            valid_validity_rule = validate_validity_rule(coupon_object=coupon_object)
            if not valid_validity_rule:
                return Response({"status":False, "message": "Invalid coupon!"},status=status.HTTP_406_NOT_ACCEPTABLE)
        except:
            pass

        # if products:
            valid_allowed_products_rule = validate_allowed_gyms_rule(coupon_object=coupon_object, gym=gym)
            if not valid_allowed_products_rule:
                return Response({"status":False, "message":  "Gym is not eligible for this Offer!"}, status=status.HTTP_406_NOT_ACCEPTABLE)


        initial_value = request.data.get('initial_amount')
        new_price = coupon_object.get_discounted_value(initial_value)
        # coupon_object.use_coupon(user)
        d={
            'initial_price':initial_value,
            'promocode_discount':Decimal(float(initial_value))-new_price,
            'final_price':new_price,
            'promocode_applied':coupon_code,
            'promocode_id': coupon_object.uuid
        }

        return Response({"status": True, "message":'Promocode Applied',"data":d},status=status.HTTP_200_OK)


class RemovePromocode(APIView):

    def post(self,request):
        data=request.data
        if not request.user.is_authenticated:
            return Response({"status":False,"message":'Unauthorized'})

        promocode_id = data.get('promocode_id')
        # offers = Offers.objects.get(uuid=promocode_id)
        coupon_user_obj = CouponUser.objects.get(user=request.user.uuid,coupon=promocode_id)
        context = {'promocode_discount':0}

        coupon_user_obj.delete()
        return Response({"status":True, "message": 'Promocode removed',"data":context},status=status.HTTP_200_OK)


class Invoice(APIView):
    def get(self,request):
        data = request.GET
        query = Subscription.objects.filter(gym = data.get('gym'))
        context =[]
        for val in query:
            ser = SubscriptionSerializer(val).data
            user = val.subscription_user.first_name
            package = val.package.package_name
            created_at = val.created_at.strftime('%d %b %y')
            amount = val.package.package_price
            ser.update({
                'subscription_user':user,
                'package':package,
                'created_at':created_at,
                'amount':amount
            })
            context.append(ser)
        return Response(context)

class export_to_csv(APIView):
    def get(self,request):
        invoices = list(
            Subscription.objects.filter().values('subscription_user__first_name','subscription_user__last_name','membership_purchased','membership_validity','package__package_name','subscription_validity','subscription_status','fee_status').order_by('-created_at'))

        for i in invoices:
            i['subscription_user'] = i['subscription_user__first_name'] + ' ' + i['subscription_user__last_name']
            i['package'] = i['package__package_name']
            i['subscription_validity'] = i['subscription_validity'].strftime("%d-%m-%Y")



        invoices = pd.DataFrame(invoices)
        invoices = invoices.to_csv('media/invoicedata.csv')
        url = 'http://127.0.0.1:8000/media/invoicedata.csv'
        return Response(url)
        
class InvoiceDetail(APIView):
    def get(self,request,uuid):
        
        value = Subscription.objects.get(uuid = uuid)
        ser = SubscriptionSerializer(value).data
        date = value.created_at.strftime('%d %b %y')
        package = value.package.package_name
        amount = value.package.package_price
        email = value.subscription_user.email
        ph_no= value.subscription_user.phone_number
        passes = value.package.class_passes

        ser.update({
            'created_at':date,
            'package':package,
            'amount':amount,
            'email':email,
            'ph_no':ph_no,
            'passes':passes
        })
        return Response(ser)
        
    def patch(self,request,uuid):
        data = request.data
        
        if not Subscription.objects.filter(uuid=uuid).exists():
            return Response('Unauthorized')
        value = Subscription.objects.get(uuid=uuid)
        ser = SubscriptionSerializer(value,data=data,partial=True)
        if ser.is_valid(raise_exception=True):
            ser.save()
            return Response(('Details saved',ser.data))
        else:
            return Response(ser.errors)
            
    def delete(self, request, uuid):
        
        snippet = Subscription.objects.get(uuid = uuid)
        snippet.delete()
        return Response({'data':"Deleted"})

