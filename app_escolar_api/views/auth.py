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

logger = logging.getLogger(_name_)

class CustomAuthToken(ObtainAuthToken):

    def post(self, request, *args, **kwargs):
        # Log para depuración
        logger.info(f"Usuario intentando login: {request.data.get('username', 'No username provided')}")
        
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
            role_names = role_names[0] if role_names else None
            
            # Generar token
            token, created = Token.objects.get_or_create(user=user)
            
            # Normalizar rol (lowercase y aceptar singular/plural)
            role_normalized = role_names.lower() if role_names else ""
            
            # Verificar que tipo de usuario quiere iniciar sesión
            if role_normalized in ['alumno', 'alumnos']:
                alumno = Alumnos.objects.filter(user=user).first()
                if not alumno:
                    return Response({"details": "Perfil de alumno no encontrado"}, 404)
                alumno_data = AlumnoSerializer(alumno).data
                alumno_data["token"] = token.key
                alumno_data["rol"] = "alumno"
                logger.info(f"Login exitoso como alumno: {user.username}")
                return Response(alumno_data, 200)
                
            elif role_normalized in ['maestro', 'maestros']:
                maestro = Maestros.objects.filter(user=user).first()
                if not maestro:
                    return Response({"details": "Perfil de maestro no encontrado"}, 404)
                maestro_data = MaestroSerializer(maestro).data
                maestro_data["token"] = token.key
                maestro_data["rol"] = "maestro"
                logger.info(f"Login exitoso como maestro: {user.username}")
                return Response(maestro_data, 200)
                
            elif role_normalized in ['administrador', 'administradores']:
                user_data = UserSerializer(user, many=False).data
                user_data['token'] = token.key
                user_data["rol"] = "administrador"
                logger.info(f"Login exitoso como administrador: {user.username}")
                return Response(user_data, 200)
                
            else:
                logger.warning(f"Rol no reconocido: {role_names} para usuario {user.username}")
                return Response({"details": "Rol no reconocido", "rol_recibido": role_names}, 403)
                
        return Response({"details": "Usuario inactivo"}, status=status.HTTP_403_FORBIDDEN)


class Logout(generics.GenericAPIView):
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        user = request.user
        if user.is_active:
            token = Token.objects.get(user=user)
            token.delete()
            return Response({'logout': True})
        return Response({'logout':False})