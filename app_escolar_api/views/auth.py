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

# CORREGIDO: __name__ con doble guión bajo
logger = logging.getLogger(__name__)

class CustomAuthToken(ObtainAuthToken):

    def post(self, request, *args, **kwargs):
        # Log para debug
        logger.info(f"Login attempt with data: {request.data}")
        
        serializer = self.serializer_class(data=request.data,
                                        context={'request': request})

        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        
        logger.info(f"User found: {user.username}, Active: {user.is_active}")
        
        if user.is_active:
            # Obtener perfil y roles del usuario
            roles = user.groups.all()
            role_names = []
            
            # Verifico si el usuario tiene un perfil asociado
            for role in roles:
                role_names.append(role.name)
                
            logger.info(f"User roles: {role_names}")

            # Si solo es un rol especifico asignamos el elemento 0
            # MANTENER LA MISMA LÓGICA QUE ANTES
            if not role_names:
                logger.warning(f"No roles for user: {user.username}")
                return Response({"details":"Usuario sin roles asignados"}, 403)
                
            role_names = role_names[0]
            
            #Esta función genera la clave dinámica (token) para iniciar sesión
            token, created = Token.objects.get_or_create(user=user)
            
            # Verificar que tipo de usuario quiere iniciar sesión
            # MANTENER COMPARACIONES EXACTAS COMO ANTES
            
            if role_names == 'alumno':
                alumno = Alumnos.objects.filter(user=user).first()
                if not alumno:
                    logger.error(f"No alumno profile for user: {user.username}")
                    return Response({"details":"Perfil de alumno no encontrado"}, 404)
                    
                alumno = AlumnoSerializer(alumno).data
                alumno["token"] = token.key
                alumno["rol"] = "alumno"
                logger.info(f"Successful login as alumno: {user.username}")
                return Response(alumno,200)
                
            if role_names == 'maestro':
                maestro = Maestros.objects.filter(user=user).first()
                if not maestro:
                    logger.error(f"No maestro profile for user: {user.username}")
                    return Response({"details":"Perfil de maestro no encontrado"}, 404)
                    
                maestro = MaestroSerializer(maestro).data
                maestro["token"] = token.key
                maestro["rol"] = "maestro"
                logger.info(f"Successful login as maestro: {user.username}")
                return Response(maestro,200)
                
            if role_names == 'administrador':
                user_data = UserSerializer(user, many=False).data
                user_data['token'] = token.key
                user_data["rol"] = "administrador"
                logger.info(f"Successful login as administrador: {user.username}")
                return Response(user_data,200)
                
            else:
                logger.warning(f"Unrecognized role: {role_names} for user {user.username}")
                return Response({"details":"Rol no reconocido"}, 403)
            
        logger.warning(f"Inactive user attempt: {user.username}")
        return Response({"details":"Usuario inactivo"}, status=status.HTTP_403_FORBIDDEN)


class Logout(generics.GenericAPIView):

    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        logger.info(f"Logout attempt for user: {request.user.username}")
        
        user = request.user
        if user.is_active:
            token = Token.objects.get(user=user)
            token.delete()
            logger.info(f"Successful logout for user: {user.username}")
            return Response({'logout':True})

        logger.warning(f"Logout failed for inactive user: {user.username}")
        return Response({'logout': False})