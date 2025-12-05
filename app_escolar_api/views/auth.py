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

# Configurar logging detallado
logger = logging.getLogger(__name__)

class CustomAuthToken(ObtainAuthToken):

    def post(self, request, *args, **kwargs):
        logger.info("="*50)
        logger.info("INICIO DE LOGIN")
        logger.info(f"Datos recibidos: {request.data}")
        
        try:
            serializer = self.serializer_class(data=request.data,
                                            context={'request': request})
            serializer.is_valid(raise_exception=True)
            user = serializer.validated_data['user']
            
            logger.info(f"Usuario encontrado: {user.username}")
            logger.info(f"Usuario activo: {user.is_active}")
            
            if not user.is_active:
                logger.error("ERROR: Usuario inactivo")
                return Response(
                    {"error": "Usuario inactivo", "code": "USER_INACTIVE"},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            # Obtener roles del usuario
            roles = user.groups.all()
            role_names = [role.name for role in roles]
            
            logger.info(f"Roles del usuario: {role_names}")
            logger.info(f"Número de roles: {len(role_names)}")
            
            if not role_names:
                logger.error("ERROR: Usuario sin roles asignados")
                return Response(
                    {"error": "Usuario sin roles asignados", "code": "NO_ROLES"},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            # Tomar el primer rol
            primary_role = role_names[0]
            logger.info(f"Rol primario: {primary_role}")
            
            # Generar token
            token, created = Token.objects.get_or_create(user=user)
            logger.info(f"Token: {token.key[:20]}...")
            
            # DEBUG: Mostrar todos los datos disponibles
            logger.info(f"DEBUG - Role comparaciones:")
            logger.info(f"  primary_role == 'alumno': {primary_role == 'alumno'}")
            logger.info(f"  primary_role == 'maestro': {primary_role == 'maestro'}")
            logger.info(f"  primary_role == 'administrador': {primary_role == 'administrador'}")
            
            # Verificar tipo de usuario
            if primary_role == 'alumno':
                logger.info("Procesando como alumno...")
                alumno = Alumnos.objects.filter(user=user).first()
                if not alumno:
                    logger.error("ERROR: Perfil de alumno no encontrado")
                    return Response(
                        {"error": "Perfil de alumno no encontrado", "code": "NO_ALUMNO_PROFILE"},
                        status=status.HTTP_404_NOT_FOUND
                    )
                alumno_data = AlumnoSerializer(alumno).data
                alumno_data["token"] = token.key
                alumno_data["rol"] = "alumno"
                logger.info("LOGIN EXITOSO como alumno")
                return Response(alumno_data, 200)
                
            elif primary_role == 'maestro':
                logger.info("Procesando como maestro...")
                maestro = Maestros.objects.filter(user=user).first()
                if not maestro:
                    logger.error("ERROR: Perfil de maestro no encontrado")
                    return Response(
                        {"error": "Perfil de maestro no encontrado", "code": "NO_MAESTRO_PROFILE"},
                        status=status.HTTP_404_NOT_FOUND
                    )
                maestro_data = MaestroSerializer(maestro).data
                maestro_data["token"] = token.key
                maestro_data["rol"] = "maestro"
                logger.info("LOGIN EXITOSO como maestro")
                return Response(maestro_data, 200)
                
            elif primary_role == 'administrador':
                logger.info("Procesando como administrador...")
                user_data = UserSerializer(user, many=False).data
                user_data['token'] = token.key
                user_data["rol"] = "administrador"
                logger.info("LOGIN EXITOSO como administrador")
                return Response(user_data, 200)
                
            else:
                logger.error(f"ERROR: Rol no reconocido: '{primary_role}'")
                logger.error(f"Roles disponibles en sistema: {list(Group.objects.all().values_list('name', flat=True))}")
                return Response(
                    {"error": f"Rol '{primary_role}' no reconocido", "code": "UNKNOWN_ROLE"},
                    status=status.HTTP_403_FORBIDDEN
                )
                
        except Exception as e:
            logger.error(f"EXCEPCIÓN: {str(e)}")
            import traceback
            logger.error(traceback.format_exc())
            return Response(
                {"error": "Error interno del servidor", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        finally:
            logger.info("FIN DE LOGIN")
            logger.info("="*50)


class Logout(generics.GenericAPIView):
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        logger.info(f"Logout para usuario: {request.user.username}")
        user = request.user
        if user.is_active:
            token = Token.objects.get(user=user)
            token.delete()
            logger.info("Logout exitoso")
            return Response({'logout': True})
        return Response({'logout': False})