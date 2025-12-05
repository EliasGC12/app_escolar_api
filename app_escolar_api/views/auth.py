import logging
from django.db.models import *
from app_escolar_api.serializers import *
from app_escolar_api.models import *
from rest_framework import permissions
from rest_framework import generics
from rest_framework import status
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

logger = logging.getLogger(__name__)

@method_decorator(csrf_exempt, name='dispatch')
class CustomAuthToken(ObtainAuthToken):
    """Login con CSRF desactivado"""

    def post(self, request, *args, **kwargs):
        logger.info(f"Login attempt for user: {request.data.get('username', 'unknown')}")
        
        serializer = self.serializer_class(data=request.data,
                                        context={'request': request})

        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        
        if user.is_active:
            # Obtener perfil y roles del usuario
            roles = user.groups.all()
            role_names = []
            
            for role in roles:
                role_names.append(role.name)

            # Si solo es un rol especifico asignamos el elemento 0
            role_names = role_names[0]
            logger.info(f"User role: {role_names}")  # Para debug
            
            # Generar token
            token, created = Token.objects.get_or_create(user=user)
            
            # Verificar que tipo de usuario quiere iniciar sesión
            # ACEPTAR TANTO SINGULAR COMO PLURAL
            if role_names in ['alumno', 'alumnos']:
                alumno = Alumnos.objects.filter(user=user).first()
                if alumno is None:
                    logger.error(f"No se encontró perfil de alumno para {user.username}")
                    return Response({"details":"Perfil de alumno no encontrado"}, 404)
                alumno_data = AlumnoSerializer(alumno).data
                alumno_data["token"] = token.key
                alumno_data["rol"] = "alumno"  # Siempre devolver singular
                logger.info(f"Login successful as alumno: {user.username}")
                return Response(alumno_data, 200)
                
            if role_names in ['maestro', 'maestros']:
                maestro = Maestros.objects.filter(user=user).first()
                if maestro is None:
                    logger.error(f"No se encontró perfil de maestro para {user.username}")
                    return Response({"details":"Perfil de maestro no encontrado"}, 404)
                maestro_data = MaestroSerializer(maestro).data
                maestro_data["token"] = token.key
                maestro_data["rol"] = "maestro"
                logger.info(f"Login successful as maestro: {user.username}")
                return Response(maestro_data, 200)
                
            if role_names in ['administrador', 'administradores', 'admin']:
                user_data = UserSerializer(user, many=False).data
                user_data['token'] = token.key
                user_data["rol"] = "administrador"
                logger.info(f"Login successful as administrador: {user.username}")
                return Response(user_data, 200)
            else:
                logger.warning(f"Unknown role: {role_names} for user {user.username}")
                return Response({"details":"Rol no reconocido", "rol_recibido": role_names}, 403)
            
        logger.warning(f"Inactive user attempt: {user.username}")
        return Response({"details":"Usuario inactivo"}, status=status.HTTP_403_FORBIDDEN)


@method_decorator(csrf_exempt, name='dispatch')
class Logout(generics.GenericAPIView):
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        user = request.user
        if user.is_active:
            token = Token.objects.get(user=user)
            token.delete()
            return Response({'logout': True})
        return Response({'logout': False})