import random
from django.core.mail import send_mail
from django.contrib.auth.hashers import make_password
from django.shortcuts import get_object_or_404
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView

from paramaxApp.models import UserAccount, OTP
from paramaxApp.serializers import UserCreateSerializer, UserAccountSerializer, CustomUserSerializer


class UserViewSet(viewsets.ViewSet):
    permission_classes_by_action = {'create': [AllowAny], 'verify_otp': [AllowAny], 'default': [IsAuthenticated]}

    def get_permissions(self):
        return [permission() for permission in self.permission_classes_by_action.get(self.action, self.permission_classes_by_action['default'])]

    def list(self, request):
        users = UserAccount.objects.all()
        serializer = UserAccountSerializer(users, many=True, context={"request": request})
        response_data = serializer.data
        response_dict = {"error": False, "message": "All Users List Data", "data": response_data}
        return Response(response_dict)

    def create(self, request):
        serializer = UserCreateSerializer(data=request.data)
        if serializer.is_valid():
            # Hash the password before saving the user
            password = make_password(serializer.validated_data['password'])
            serializer.validated_data['password'] = password

            # Generate OTP
            otp = random.randint(100000, 999999)
            email = serializer.validated_data['email']

            # Send OTP to email
            send_mail(
                'Your OTP Code',
                f'Your OTP code is {otp}',
                'from@example.com',
                [email],
                fail_silently=False,
            )

            # Save OTP to the database
            OTP.objects.create(email=email, otp=otp)

            # Set the user as inactive
            serializer.validated_data['is_active'] = False
            serializer.save()

            # Save user data temporarily
            request.session['temp_user_email'] = email

            return Response({'message': 'OTP sent to email'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def verify_otp(self, request):
        otp = request.data.get('otp')
        email = request.session.get('temp_user_email')

        if not (otp and email):
            return Response({'error': 'Missing data'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            otp_record = OTP.objects.get(email=email, otp=otp)
        except OTP.DoesNotExist:
            return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

        if not otp_record.is_valid():
            return Response({'error': 'OTP expired'}, status=status.HTTP_400_BAD_REQUEST)

        # Activate the user
        try:
            user = UserAccount.objects.get(email=email)
            user.is_active = True
            user.save()
        except UserAccount.DoesNotExist:
            return Response({'error': 'User does not exist'}, status=status.HTTP_400_BAD_REQUEST)

        # Clear session data and delete OTP
        del request.session['temp_user_email']
        otp_record.delete()

        return Response({'message': 'User activated successfully'}, status=status.HTTP_201_CREATED)

    def retrieve(self, request, pk=None):
        queryset = UserAccount.objects.all()
        user = get_object_or_404(queryset, pk=pk)
        serializer = UserAccountSerializer(user)
        return Response(serializer.data)

    def update(self, request, pk=None):
        user = UserAccount.objects.get(pk=pk)
        serializer = UserAccountSerializer(user, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        user = UserAccount.objects.get(pk=pk)
        serializer = UserAccountSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        user = UserAccount.objects.get(pk=pk)
        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class AdminUserViewSet(viewsets.ViewSet):
    permission_classes_by_action = {
        'create': [AllowAny],
        'verify_otp': [AllowAny],
        'default': [IsAuthenticated]
    }

    def get_permissions(self):
        return [permission() for permission in self.permission_classes_by_action.get(self.action, self.permission_classes_by_action['default'])]

    def create(self, request):
        serializer = UserCreateSerializer(data=request.data)
        if serializer.is_valid():
            # Hash the password before saving the user
            password = make_password(serializer.validated_data['password'])
            serializer.validated_data['password'] = password

            # Generate OTP
            otp = random.randint(100000, 999999)
            email = serializer.validated_data['email']

            # Send OTP to email
            send_mail(
                'Your OTP Code',
                f'Your OTP code is {otp}',
                'from@example.com',
                [email],
                fail_silently=False,
            )

            # Save OTP to the database
            OTP.objects.create(email=email, otp=otp)

            # Set the user as inactive
            serializer.validated_data['is_active'] = False
            serializer.save()

            # Save user data temporarily
            request.session['temp_user_email'] = email

            return Response({'message': 'OTP sent to email'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def verify_otp(self, request):
        otp = request.data.get('otp')
        email = request.session.get('temp_user_email')

        if not (otp and email):
            return Response({'error': 'Missing data'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            otp_record = OTP.objects.get(email=email, otp=otp)
        except OTP.DoesNotExist:
            return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

        if not otp_record.is_valid():
            return Response({'error': 'OTP expired'}, status=status.HTTP_400_BAD_REQUEST)

        # Activate the user and set them as admin
        try:
            user = UserAccount.objects.get(email=email)
            user.is_active = True
            user.is_staff = True
            user.user_type = 'admin'
            user.save()
        except UserAccount.DoesNotExist:
            return Response({'error': 'User does not exist'}, status=status.HTTP_400_BAD_REQUEST)

        # Clear session data and delete OTP
        del request.session['temp_user_email']
        otp_record.delete()

        return Response({'message': 'User activated successfully'}, status=status.HTTP_201_CREATED)

    def retrieve(self, request, pk=None):
        queryset = UserAccount.objects.all()
        user = get_object_or_404(queryset, pk=pk)
        serializer = UserAccountSerializer(user)
        return Response(serializer.data)

    def update(self, request, pk=None):
        user = UserAccount.objects.get(pk=pk)
        serializer = UserAccountSerializer(user, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        user = UserAccount.objects.get(pk=pk)
        serializer = UserAccountSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        user = UserAccount.objects.get(pk=pk)
        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class UserInfoView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        serializer = CustomUserSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)