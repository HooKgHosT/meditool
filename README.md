<p align="center">MediTool: Herramienta de Seguridad para Blue Team</p>
MediTool es un script de PowerShell diseñado para equipos de seguridad (Blue Team) y usuarios avanzados. Proporciona una suite de herramientas para auditar, verificar y mitigar vulnerabilidades comunes en sistemas Windows 10 y Windows 11.

El script se auto-gestiona: se descarga, se eleva a permisos de administrador si es necesario y luego se borra para no dejar rastros en el sistema.

:rocket: Características
Verificación de Seguridad: Audita puertos abiertos, telemetría de Windows, y el estado del servicio de Escritorio Remoto (RDP).

Análisis de Archivos y Procesos: Busca archivos y procesos en ejecución sin firma digital, lo que puede indicar la presencia de malware.

Gestión de Cuentas de Usuario: Identifica usuarios inactivos y analiza la política de contraseñas.

Análisis de Red y Registro: Examina conexiones de red sospechosas y entradas de registro de inicio automático (Autorun).

Reportes de Seguridad: Genera un reporte detallado en formato HTML para una revisión más sencilla.

Utilitarios Adicionales: Incluye herramientas para cambiar la dirección MAC, actualizar aplicaciones con winget, limpiar archivos temporales y activar Windows de forma no oficial.

:card_file_box: Archivo del Código
meditool.ps1: El script principal de la herramienta.

:gear: Cómo usarlo
Para ejecutar MediTool, simplemente abre una terminal de PowerShell como Administrador y ejecuta el siguiente comando.

Importante: El script se auto-elevará si no tienes permisos de administrador, pero es recomendable ejecutar la terminal directamente con privilegios elevados para evitar el mensaje de confirmación de Windows.

PowerShell

"irm https://raw.githubusercontent.com/HooKgHosT/meditool/main/comprobarRDP.ps1 | iex"

Al ejecutarlo, el script se descargará temporalmente, se relanzará con permisos de administrador (si no los tiene) y te presentará un menú interactivo con todas las opciones disponibles.

:camera: Capturas de Pantalla
Aquí puedes agregar capturas de pantalla de la terminal mostrando el menú y los resultados del script para que los usuarios puedan ver cómo funciona.

:page_with_curl: Licencia
Este proyecto está bajo la licencia MIT. Puedes ver el archivo LICENSE para más detalles.

:busts_in_silhouette: Contacto
Para sugerencias o reportar errores, puedes contactar a h00kGh0st a través de GitHub.
