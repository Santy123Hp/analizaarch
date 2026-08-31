# AnalizaArch — Guía rápida

## Qué es
Herramienta de escritorio que usa la API de VirusTotal para revisar
si un archivo ha sido detectado como amenaza por otros antivirus.

No es un antivirus en tiempo real: solo analiza el archivo que tú
selecciones manualmente.

## Cómo usarlo
1. Descarga la versión de tu sistema desde la sección "Releases".
2. Al abrirlo por primera vez, te pedirá una API key gratuita de
   VirusTotal (el programa tiene un botón para ayudarte a crearla).
3. Selecciona "Escanear" en el menú, elige un archivo y revisa el
   resultado.

## Advertencia sobre antivirus
Algunos antivirus pueden marcar el .exe como falso positivo por no
tener firma digital todavía. Puedes revisar el análisis completo de
VirusTotal en la descripción de cada Release.

## Privacidad
Tus archivos no se suben ni se guardan en ningún lado; solo se
consulta su hash (huella digital) contra la base de VirusTotal.
