import random
from datetime import timedelta

from django.core.mail import send_mail
from django.contrib.auth.hashers import make_password
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import viewsets, status
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication

from paramaxApp.models import UserAccount, OTP, Category, Services
from paramaxApp.serializers import UserCreateSerializer, UserAccountSerializer, CustomUserSerializer, \
    CategorySerializer, ServiceSerializer


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def search(request):
    query = request.GET.get('query', '')

    if not query:
        return Response({"error": True, "message": "Query parameter is required"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        categories = Category.objects.filter(category_name__icontains=query)
        services = Services.objects.filter(service_name__icontains=query)

        category_serializer = CategorySerializer(categories, many=True, context={"request": request})
        service_serializer = ServiceSerializer(services, many=True, context={"request": request})

        response_data = {
            "categories": category_serializer.data,
            "services": service_serializer.data
        }

        return Response({"error": False, "message": "Search Results", "data": response_data}, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({"error": True, "message": "An error occurred", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserViewSet(viewsets.ViewSet):
    permission_classes_by_action = {'create': [AllowAny], 'list': [IsAdminUser], 'verify_otp': [AllowAny], 'default': [IsAuthenticated]}

    def get_permissions(self):
        return [permission() for permission in self.permission_classes_by_action.get(self.action, self.permission_classes_by_action['default'])]

    def list(self, request):
        try:
            users = UserAccount.objects.all()
            serializer = UserAccountSerializer(users, many=True, context={"request": request})
            response_data = serializer.data
            response_dict = {"error": False, "message": "All Users List Data", "data": response_data}

        except ValidationError as e:
            response_dict = {"error": True, "message": "Validation Error", "details": str(e)}
        except Exception as e:
            response_dict = {"error": True, "message": "An Error Occurred", "details": str(e)}

        return Response(response_dict,
                        status=status.HTTP_400_BAD_REQUEST if response_dict['error'] else status.HTTP_200_OK)

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

            # Save OTP and email in session
            request.session['otp'] = otp
            request.session['email'] = email

            return Response({'message': 'OTP sent to email'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def verify_otp(self, request):
        otp = request.data.get('otp')

        if not otp:
            return Response({'error': 'Missing OTP'}, status=status.HTTP_400_BAD_REQUEST)

        email = request.session.get('email')
        session_otp = request.session.get('otp')

        if otp != str(session_otp):
            return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

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
        del request.session['otp']
        del request.session['email']
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

            # Save OTP and email in session
            request.session['otp'] = otp
            request.session['email'] = email

            return Response({'message': 'OTP sent to email'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def verify_otp(self, request):
        otp = request.data.get('otp')

        if not otp:
            return Response({'error': 'Missing OTP'}, status=status.HTTP_400_BAD_REQUEST)

        email = request.session.get('email')
        session_otp = request.session.get('otp')

        if otp != str(session_otp):
            return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            otp_record = OTP.objects.get(email=email, otp=otp)
        except OTP.DoesNotExist:
            return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

        if not otp_record.is_valid():
            return Response({'error': 'OTP expired'}, status=status.HTTP_400_BAD_REQUEST)

        # Activate the user and set them as admin
        try:
            user = UserAccount.objects.get(email=email)
            user.is_superuser= True
            user.is_active = True
            user.is_staff = True
            user.user_type = 'admin'
            user.save()
        except UserAccount.DoesNotExist:
            return Response({'error': 'User does not exist'}, status=status.HTTP_400_BAD_REQUEST)

        # Clear session data and delete OTP
        del request.session['otp']
        del request.session['email']
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


class CategoryViewSet(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def list(self, request):
        try:
            categories = Category.objects.all()
            serializer = CategorySerializer(categories, many=True, context={"request": request})
            response_data = serializer.data
            response_dict = {"error": False, "message": "All Categories", "data": response_data}

        except ValidationError as e:
            response_dict = {"error": True, "message": "Validation Error", "details": str(e)}
        except Exception as e:
            response_dict = {"error": True, "message": "An Error Occurred", "details": str(e)}

        return Response(response_dict,
                        status=status.HTTP_400_BAD_REQUEST if response_dict['error'] else status.HTTP_200_OK)

    def create(self, request):
        if not request.user.is_staff:
            return Response({"error": True, "message": "User does not have enough permission to perform this task"},
                            status=status.HTTP_401_UNAUTHORIZED)

        try:
            serializer = CategorySerializer(data=request.data, context={"request": request})
            serializer.is_valid(raise_exception=True)
            serializer.save()
            dict_response = {"error": False, "message": "Category created Successfully"}

        except ValidationError as e:
            dict_response = {"error": True, "message": "Validation Error", "details": str(e)}
        except Exception as e:
            dict_response = {"error": True, "message": "An Error Occurred", "details": str(e)}

        return Response(dict_response,
                        status=status.HTTP_400_BAD_REQUEST if dict_response['error'] else status.HTTP_201_CREATED)

    def retrieve(self, request, pk=None):
        queryset = Category.objects.all()
        categories = get_object_or_404(queryset, pk=pk)
        serializer = CategorySerializer(categories, context={"request": request})

        serializer_data = serializer.data
        # return services associated with the category
        services = Services.objects.filter(category_id=serializer_data["id"])
        services_serializer = ServiceSerializer(services, many=True)
        serializer_data["services"] = services_serializer.data

        return Response({"error": False, "message": "Single Data Fetch", "data": serializer_data})

    def update(self, request, pk=None):
        if not request.user.is_staff:
            return Response({"error": True, "message": "User does not have enough permission to perform this task"},
                            status=status.HTTP_401_UNAUTHORIZED)

        try:
            queryset = Category.objects.all()
            categories = get_object_or_404(queryset, pk=pk)
            serializer = CategorySerializer(categories, data=request.data, context={"request": request})
            serializer.is_valid(raise_exception=True)
            serializer.save()
            dict_response = {"error": False, "message": "Category Updated Successfully"}

        except ValidationError as e:
            dict_response = {"error": True, "message": "Validation Error", "details": str(e)}
        except Exception as e:
            dict_response = {"error": True, "message": "An Error Occurred", "details": str(e)}

        return Response(dict_response,
                            status=status.HTTP_400_BAD_REQUEST if dict_response['error'] else status.HTTP_201_CREATED)

    def destroy(self, request, pk=None):
        if not request.user.is_staff:
            return Response({"error": True, "message": "User does not have enough permission to perform this task"},\
                            status=status.HTTP_401_UNAUTHORIZED)

        queryset = Category.objects.all()
        categories = get_object_or_404(queryset, pk=pk)
        categories.delete()
        return Response({"error": False, "message": "Category Deleted"})


class ServicesViewSet(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def list(self, request):
        try:
            services = Services.objects.all()
            serializer = ServiceSerializer(services, many=True, context={"request": request})
            response_data = serializer.data
            response_dict = {"error": False, "message": "All Services", "data": response_data}

        except ValidationError as e:
            response_dict = {"error": True, "message": "Validation Error", "details": str(e)}
        except Exception as e:
            response_dict = {"error": True, "message": "An Error Occurred", "details": str(e)}

        return Response(response_dict,
                        status=status.HTTP_400_BAD_REQUEST if response_dict['error'] else status.HTTP_200_OK)

    def create(self, request):
        if not request.user.is_staff:
            return Response({"error": True, "message": "User does not have enough permission to perform this task"},
                            status=status.HTTP_401_UNAUTHORIZED)

        try:
            serializer = ServiceSerializer(data=request.data, context={"request": request})
            serializer.is_valid(raise_exception=True)
            serializer.save()
            dict_response = {"error": False, "message": "Service created Successfully"}

        except ValidationError as e:
            dict_response = {"error": True, "message": "Validation Error", "details": str(e)}
        except Exception as e:
            dict_response = {"error": True, "message": "An Error Occurred", "details": str(e)}

        return Response(dict_response,
                        status=status.HTTP_400_BAD_REQUEST if dict_response['error'] else status.HTTP_201_CREATED)

    def retrieve(self, request, pk=None):
        queryset = Services.objects.all()
        services = get_object_or_404(queryset, pk=pk)
        serializer = ServiceSerializer(services, context={"request": request})

        return Response({"error": False, "message": "Single Data Fetch", "data": serializer.data})

    def update(self, request, pk=None):
        if not request.user.is_staff:
            return Response({"error": True, "message": "User does not have enough permission to perform this task"},
                            status=status.HTTP_401_UNAUTHORIZED)

        try:
            queryset = Services.objects.all()
            services = get_object_or_404(queryset, pk=pk)
            serializer = ServiceSerializer(services, data=request.data, context={"request": request})
            serializer.is_valid(raise_exception=True)
            serializer.save()
            dict_response = {"error": False, "message": "Service Updated Successfully"}

        except ValidationError as e:
            dict_response = {"error": True, "message": "Validation Error", "details": str(e)}
        except Exception as e:
            dict_response = {"error": True, "message": "An Error Occurred", "details": str(e)}

        return Response(dict_response,
                            status=status.HTTP_400_BAD_REQUEST if dict_response['error'] else status.HTTP_201_CREATED)

    def destroy(self, request, pk=None):
        if not request.user.is_staff:
            return Response({"error": True, "message": "User does not have enough permission to perform this task"},\
                            status=status.HTTP_401_UNAUTHORIZED)

        queryset = Services.objects.all()
        services = get_object_or_404(queryset, pk=pk)
        services.delete()
        return Response({"error": False, "message": "Service Deleted"})
