<p align="center">MediTool: Herramienta de Seguridad para Blue Team</p>

MediTool es un script de PowerShell diseñado para equipos de seguridad (Blue Team) y usuarios avanzados. Proporciona una suite de herramientas para auditar, verificar y mitigar vulnerabilidades comunes en sistemas Windows 10 y Windows 11.
El script se auto-gestiona: se descarga, no se eleva a permisos de administrador hay que ejecutar el powershell como administrador y luego lanzar el comando posteriormente, una vez utilizado, se borra para no dejar rastros en el sistema.

:rocket: Características :rocket:

Verificación de Seguridad: Audita puertos abiertos, telemetría de Windows, y el estado del servicio de Escritorio Remoto (RDP).
Análisis de Archivos y Procesos: Busca archivos y procesos en ejecución sin firma digital, lo que puede indicar la presencia de malware.
Gestión de Cuentas de Usuario: Identifica usuarios inactivos y analiza la política de contraseñas.
Análisis de Red y Registro: Examina conexiones de red sospechosas y entradas de registro de inicio automático (Autorun).
Reportes de Seguridad: Genera un reporte detallado en formato HTML para una revisión más sencilla.
Utilitarios Adicionales: Incluye herramientas para cambiar la dirección MAC, actualizar aplicaciones con winget, limpiar archivos temporales y activar Windows de forma no oficial.

:card_file_box: Archivo del Código:

meditool.ps1: El script principal de la herramienta.

:gear: Cómo usarlo :gear:

¡¡IMPORTANTE!!: Es recomendable ejecutar la terminal directamente con privilegios elevados para evitar errores de ejecución..

<p align="center">"irm https://raw.githubusercontent.com/HooKgHosT/meditool/main/comprobarRDP.ps1 | iex" </p>

Al ejecutarlo, el script se descargará temporalmente, se relanzará con permisos de administrador (si no los tiene) y te presentará un menú interactivo con todas las opciones disponibles.

:camera: Capturas de Pantalla :camera:
<img width="857" height="701" alt="screen1" src="https://github.com/user-attachments/assets/fc450926-ef24-4549-92e0-186a325413d7" />
<img width="857" height="697" alt="screen2" src="https://github.com/user-attachments/assets/bdfffaa0-fdfd-4478-97ec-b33ca4b69b30" />
<img width="861" height="701" alt="screen3" src="https://github.com/user-attachments/assets/ea54858e-0f4a-447d-92cb-4613460497bc" />


:page_with_curl: Licencia :page_with_curl:

Este proyecto está bajo la licencia MIT. Puedes ver el archivo LICENSE para más detalles.

<p align="center">:busts_in_silhouette: Contacto :busts_in_silhouette: </p>

Para sugerencias, reportes de errores o si quieres contribuir, puedes contactarme a través de:

GitHub: @HooKgHosT

LinkedIn: D4N1FEIJ00

Discord: Me puedes encontrar como ELMOnymous en el servidor de EvilSec.

