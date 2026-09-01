import tkinter as tk
from tkinter import messagebox, filedialog
import webbrowser
import os
import sys
import json
import hashlib
import threading
import base64
import requests

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    ARRASTRAR_DISPONIBLE = True
except ImportError:
    ARRASTRAR_DISPONIBLE = False

try:
    import pystray
    from PIL import Image as PILImage
    import io
    BANDEJA_DISPONIBLE = True
except ImportError:
    BANDEJA_DISPONIBLE = False

APP_NAME = "AnalizaArch"
VERSION = "0.4"

CONFIG_FILE = os.path.join(os.path.expanduser("~"), ".analizaarch_config.json")
VT_APIKEY_URL = "https://www.virustotal.com/gui/my-apikey"
VT_API_URL = "https://www.virustotal.com/api/v3/files/{hash}"
VT_API_URL_ANALISIS = "https://www.virustotal.com/api/v3/urls"
VT_API_URL_ESTADO = "https://www.virustotal.com/api/v3/analyses/{id}"
DONACION_URL = "https://github.com/Santy123Hp/analizaarch#te-sirvio-analizaarch"

ICONO_B64 = "iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAACZklEQVR4nO2bPU4DMRCFH4h+b5AjUKSgokmfu+QsuQt9GioKihwhN8gJoEBB1sb2zr+9ij8JiSTs2u/N2PGaMTAYDAYNmTbvPy3bf2rRaE309fIZ2qfQxlLh0+bt7vPr5Sv5PcYI90bm0c4Jn5Ma8ffazwy3Gy9Fm4p3VpjeUBJtKl5Zob6JVvS03eP6/cG6xtIM8YXaFJ+2+7v3uEYA+iHCusAi2lSisoL0Rx7RpuKdFcUPI6NNxSMrFg3oQfgcqRE5A14sOhQhutSeZIikqAyIFl7rg9QItgE9iM4hzYpnj854cj7uTO+3KgNu4s/HnZkRqzEgJ9jCiNUYUOL1cFJdvwoDSlHWigdWYID1pDenawNq4i2iD3RsQIR4oFMDosQDnRpQwlo80KEBnjN+jq4M8J7xc7gZwBUTOe5TzA1Il6dUE1qJBwQGlB41S+tyTVpLxHP3BYoG3LaP5vtqJaSR8p70atthgHAIlFwudbok0nrSk+wKVQ3gZkGNudiIcb8UfUAxCXKzAABpcpSKl+4JLhogyQKKCdzruFCiDyi/Bmuuc8VoxGu2xkkGSOcCqijr73pq9AGDhZD2HxOt2ycb4JUFLaMPGC2Fl6JwE/l6OP3/pO97tUsh7GlwLtZ7jU+FZUBtGETPBbn2uOkPdLYf0AL+02AHWWAVfWBkgL5KrFRBElkiI40+YFQhkiPtbHSRFAdVoSS3jsijTE4TfcAxA3IsZUWLZbVZqay0LlhSKntDG32gg1phCV3UCuewKpEv4VE673JewDIrvA9PjBMjXjfO8ZBnhnL0dGqsOa3PDQ4GD84vttWG54T+OmwAAAAASUVORK5CYII="

TEMAS = {
    "claro": {"bg": "#f4f4f4", "fg": "#1a1a1a", "bg_panel": "#ffffff", "sub": "#555555", "hover": "#e2e8f0", "acento": "#2d6ebe"},
    "oscuro": {"bg": "#1e1e1e", "fg": "#eaeaea", "bg_panel": "#2b2b2b", "sub": "#9a9a9a", "hover": "#3a3a3a", "acento": "#4a90d9"},
}

TAMANOS_FUENTE = {"pequeno": 9, "mediano": 11, "grande": 14}

CONFIG_POR_DEFECTO = {"api_key": "", "tema": "claro", "tamano": "mediano", "primera_vez": True}

BaseVentana = TkinterDnD.Tk if ARRASTRAR_DISPONIBLE else tk.Tk


def crear_boton(parent, texto, comando, colores, ancho=None, primario=False, **kwargs):
    bg_normal = colores["acento"] if primario else colores["bg_panel"]
    fg_normal = "#ffffff" if primario else colores["fg"]
    boton = tk.Button(
        parent, text=texto, command=comando, width=ancho, relief="flat",
        bg=bg_normal, fg=fg_normal, activebackground=colores["hover"], activeforeground=colores["fg"],
        cursor="hand2", bd=0, highlightthickness=0, **kwargs
    )

    def _entrar(evento):
        boton.config(bg=colores["hover"] if not primario else colores["acento"])

    def _salir(evento):
        boton.config(bg=bg_normal)

    boton.bind("<Enter>", _entrar)
    boton.bind("<Leave>", _salir)
    return boton


def estilizar_entry(entry, colores):
    entry.config(
        bg=colores["bg_panel"], fg=colores["fg"], insertbackground=colores["fg"],
        relief="flat", highlightthickness=1, highlightbackground=colores["sub"],
        highlightcolor=colores["acento"]
    )
    return entry


def _ofuscar(texto):
    return base64.b64encode(texto.encode("utf-8")).decode("utf-8")


def _desofuscar(texto):
    try:
        return base64.b64decode(texto.encode("utf-8")).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return ""


def cargar_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                config = CONFIG_POR_DEFECTO.copy()
                config.update(data)
                if config.get("api_key"):
                    config["api_key"] = _desofuscar(config["api_key"])
                return config
        except (json.JSONDecodeError, OSError):
            return CONFIG_POR_DEFECTO.copy()
    return CONFIG_POR_DEFECTO.copy()


def guardar_config(config):
    config_a_guardar = config.copy()
    if config_a_guardar.get("api_key"):
        config_a_guardar["api_key"] = _ofuscar(config_a_guardar["api_key"])
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config_a_guardar, f)


def calcular_sha256(ruta_archivo):
    sha256 = hashlib.sha256()
    with open(ruta_archivo, "rb") as f:
        for bloque in iter(lambda: f.read(8192), b""):
            sha256.update(bloque)
    return sha256.hexdigest()


def consultar_virustotal(hash_archivo, api_key):
    headers = {"x-apikey": api_key}
    url = VT_API_URL.format(hash=hash_archivo)
    respuesta = requests.get(url, headers=headers, timeout=30)

    if respuesta.status_code == 200:
        datos = respuesta.json()
        stats = datos["data"]["attributes"]["last_analysis_stats"]
        return {
            "encontrado": True,
            "maliciosos": stats.get("malicious", 0),
            "sospechosos": stats.get("suspicious", 0),
            "inofensivos": stats.get("harmless", 0),
            "sin_detectar": stats.get("undetected", 0),
        }
    elif respuesta.status_code == 404:
        return {"encontrado": False}
    elif respuesta.status_code == 401:
        raise ValueError("API key invalida. Revisa que la hayas copiado bien.")
    elif respuesta.status_code == 429:
        raise ValueError("Limite de consultas alcanzado. Intenta de nuevo mas tarde (se resetea cada 24 horas).")
    else:
        raise ValueError(f"Error inesperado del servidor (codigo {respuesta.status_code}).")


def consultar_url_virustotal(url, api_key):
    import time
    headers = {"x-apikey": api_key}
    id_url = base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").strip("=")

    respuesta = requests.get(f"{VT_API_URL_ANALISIS}/{id_url}", headers=headers, timeout=30)

    if respuesta.status_code == 200:
        stats = respuesta.json()["data"]["attributes"]["last_analysis_stats"]
        return {
            "encontrado": True, "id_url": id_url,
            "maliciosos": stats.get("malicious", 0), "sospechosos": stats.get("suspicious", 0),
            "inofensivos": stats.get("harmless", 0), "sin_detectar": stats.get("undetected", 0),
        }
    elif respuesta.status_code == 404:
        respuesta_envio = requests.post(VT_API_URL_ANALISIS, headers=headers, data={"url": url}, timeout=30)
        if respuesta_envio.status_code not in (200, 201):
            raise ValueError(f"No se pudo enviar la URL para analisis (codigo {respuesta_envio.status_code}).")
        id_analisis = respuesta_envio.json()["data"]["id"]

        for _ in range(5):
            time.sleep(3)
            resp_estado = requests.get(VT_API_URL_ESTADO.format(id=id_analisis), headers=headers, timeout=30)
            if resp_estado.status_code == 200:
                datos_estado = resp_estado.json()["data"]["attributes"]
                if datos_estado.get("status") == "completed":
                    stats = datos_estado["stats"]
                    return {
                        "encontrado": True, "id_url": id_url,
                        "maliciosos": stats.get("malicious", 0), "sospechosos": stats.get("suspicious", 0),
                        "inofensivos": stats.get("harmless", 0), "sin_detectar": stats.get("undetected", 0),
                    }
        return {"encontrado": False, "id_url": id_url}
    elif respuesta.status_code == 401:
        raise ValueError("API key invalida. Revisa que la hayas copiado bien.")
    elif respuesta.status_code == 429:
        raise ValueError("Limite de consultas alcanzado. Intenta de nuevo mas tarde (se resetea cada 24 horas).")
    else:
        raise ValueError(f"Error inesperado del servidor (codigo {respuesta.status_code}).")


def obtener_ruta_ejecutable_actual():
    if getattr(sys, "frozen", False):
        return sys.executable
    return os.path.abspath(sys.argv[0])


def formatear_tamano(bytes_totales):
    for unidad in ["B", "KB", "MB", "GB"]:
        if bytes_totales < 1024:
            return f"{bytes_totales:.2f} {unidad}" if unidad != "B" else f"{bytes_totales} {unidad}"
        bytes_totales /= 1024
    return f"{bytes_totales:.2f} TB"


def obtener_tipo_archivo(ruta):
    import mimetypes
    tipo, _ = mimetypes.guess_type(ruta)
    if tipo:
        return tipo
    extension = os.path.splitext(ruta)[1].lower()
    return f"Archivo {extension}" if extension else "Desconocido"


def obtener_icono():
    try:
        datos = base64.b64decode(ICONO_B64)
        with open(os.path.join(os.path.expanduser("~"), ".analizaarch_icon.png"), "wb") as f:
            f.write(datos)
        return tk.PhotoImage(data=ICONO_B64)
    except (tk.TclError, OSError):
        return None


class PantallaConfiguracion(tk.Frame):
    def __init__(self, master, tema, tamano, on_key_guardada, on_cancelar=None, key_actual=""):
        colores = TEMAS[tema]
        fuente_base = TAMANOS_FUENTE[tamano]
        super().__init__(master, padx=25, pady=25, bg=colores["bg"])
        self.on_key_guardada = on_key_guardada
        self.on_cancelar = on_cancelar

        titulo = "Cambiar API key" if key_actual else "Configura tu API key de VirusTotal"
        tk.Label(
            self, text=titulo, font=("Segoe UI", fuente_base + 2, "bold"),
            bg=colores["bg"], fg=colores["fg"]
        ).pack(pady=(0, 12), anchor="w")

        tk.Label(
            self,
            text="Se necesita una API key gratuita de VirusTotal para poder\nconsultar los archivos. Si ya tienes una cuenta, solo entra\na tu panel y copiala; si no, creala en un par de minutos.",
            justify="left", bg=colores["bg"], fg=colores["fg"], font=("Segoe UI", fuente_base)
        ).pack(pady=(0, 14), anchor="w")

        tk.Button(
            self, text="Abrir mi panel de VirusTotal",
            command=lambda: webbrowser.open(VT_APIKEY_URL)
        ).pack(pady=(0, 18), anchor="w")

        tk.Label(self, text="API key:", bg=colores["bg"], fg=colores["fg"], font=("Segoe UI", fuente_base)).pack(anchor="w")
        self.entry_key = tk.Entry(self, width=52, show="*")
        estilizar_entry(self.entry_key, colores)
        self.entry_key.pack(pady=(4, 4), anchor="w")
        if key_actual:
            self.entry_key.insert(0, key_actual)

        self.mostrar_key = tk.BooleanVar(value=False)
        tk.Checkbutton(
            self, text="Mostrar", variable=self.mostrar_key, command=self._alternar_visibilidad,
            bg=colores["bg"], fg=colores["fg"], selectcolor=colores["bg_panel"], font=("Segoe UI", fuente_base)
        ).pack(anchor="w", pady=(0, 18))

        fila_botones = tk.Frame(self, bg=colores["bg"])
        fila_botones.pack(anchor="w", pady=(4, 0))

        tk.Button(fila_botones, text="Guardar", width=12, command=self._guardar).pack(side="left")

        if key_actual and self.on_cancelar:
            tk.Button(
                fila_botones, text="Cancelar", width=12, command=self.on_cancelar
            ).pack(side="left", padx=(10, 0))

    def _alternar_visibilidad(self):
        self.entry_key.config(show="" if self.mostrar_key.get() else "*")

    def _guardar(self):
        key = self.entry_key.get().strip()
        if not key:
            messagebox.showwarning("Falta la API key", "Pega tu API key antes de continuar.")
            return
        self.on_key_guardada(key)


class PantallaPreferencias(tk.Frame):
    def __init__(self, master, tema, tamano, on_guardar, on_cancelar):
        colores = TEMAS[tema]
        fuente_base = TAMANOS_FUENTE[tamano]
        super().__init__(master, padx=25, pady=25, bg=colores["bg"])
        self.on_guardar = on_guardar
        self.on_cancelar = on_cancelar

        tk.Label(
            self, text="Preferencias", font=("Segoe UI", fuente_base + 2, "bold"),
            bg=colores["bg"], fg=colores["fg"]
        ).pack(pady=(0, 16), anchor="w")

        tk.Label(self, text="Tema:", bg=colores["bg"], fg=colores["fg"], font=("Segoe UI", fuente_base)).pack(anchor="w")
        self.var_tema = tk.StringVar(value=tema)
        fila_tema = tk.Frame(self, bg=colores["bg"])
        fila_tema.pack(anchor="w", pady=(4, 16))
        tk.Radiobutton(
            fila_tema, text="Claro", variable=self.var_tema, value="claro",
            bg=colores["bg"], fg=colores["fg"], selectcolor=colores["bg_panel"]
        ).pack(side="left", padx=(0, 12))
        tk.Radiobutton(
            fila_tema, text="Oscuro", variable=self.var_tema, value="oscuro",
            bg=colores["bg"], fg=colores["fg"], selectcolor=colores["bg_panel"]
        ).pack(side="left")

        tk.Label(self, text="Tamano del texto:", bg=colores["bg"], fg=colores["fg"], font=("Segoe UI", fuente_base)).pack(anchor="w")
        self.var_tamano = tk.StringVar(value=tamano)
        fila_tamano = tk.Frame(self, bg=colores["bg"])
        fila_tamano.pack(anchor="w", pady=(4, 20))
        for etiqueta, valor in [("Pequeno", "pequeno"), ("Mediano", "mediano"), ("Grande", "grande")]:
            tk.Radiobutton(
                fila_tamano, text=etiqueta, variable=self.var_tamano, value=valor,
                bg=colores["bg"], fg=colores["fg"], selectcolor=colores["bg_panel"]
            ).pack(side="left", padx=(0, 12))

        fila_botones = tk.Frame(self, bg=colores["bg"])
        fila_botones.pack(anchor="w")
        tk.Button(
            fila_botones, text="Guardar", width=12,
            command=lambda: self.on_guardar(self.var_tema.get(), self.var_tamano.get())
        ).pack(side="left")
        tk.Button(fila_botones, text="Cancelar", width=12, command=self.on_cancelar).pack(side="left", padx=(10, 0))


class PantallaEscaneo(tk.Frame):
    def __init__(self, master, api_key, tema, tamano, archivo_inicial=None):
        colores = TEMAS[tema]
        fuente_base = TAMANOS_FUENTE[tamano]
        super().__init__(master, padx=25, pady=25, bg=colores["bg"])
        self.api_key = api_key
        self.colores = colores
        self.fuente_base = fuente_base
        self.ruta_seleccionada = None
        self.hash_actual = None
        self.tipo_resultado_actual = None
        self.historial = []

        tk.Label(
            self, text="Analizar un archivo", font=("Segoe UI", fuente_base + 2, "bold"),
            bg=colores["bg"], fg=colores["fg"]
        ).pack(pady=(0, 4), anchor="w")

        tk.Label(
            self, text="Se consulta solo la huella digital (hash) del archivo,\nsin subirlo ni enviarlo por internet.",
            fg=colores["sub"], bg=colores["bg"], font=("Segoe UI", fuente_base)
        ).pack(pady=(0, 12), anchor="w")

        tk.Button(
            self, text="Seleccionar archivo...", command=self._seleccionar_archivo
        ).pack(pady=(0, 10), anchor="w")

        if ARRASTRAR_DISPONIBLE and hasattr(master, "drop_target_register"):
            zona_arrastrar = tk.Label(
                self, text="...o arrastra un archivo aqui",
                bg=colores["bg_panel"], fg=colores["sub"], font=("Segoe UI", fuente_base),
                relief="groove", bd=2, padx=20, pady=14
            )
            zona_arrastrar.pack(pady=(0, 14), anchor="w", fill="x")
            zona_arrastrar.drop_target_register(DND_FILES)
            zona_arrastrar.dnd_bind("<<Drop>>", self._archivo_soltado)

        self.label_archivo = tk.Label(
            self, text="Ningun archivo seleccionado", fg="gray", bg=colores["bg"],
            font=("Segoe UI", fuente_base), justify="left"
        )
        self.label_archivo.pack(pady=(0, 16), anchor="w")

        self.boton_escanear = crear_boton(
            self, "Escanear", self._iniciar_escaneo, colores, ancho=14, primario=True, state="disabled"
        )
        self.boton_escanear.pack(pady=(0, 14), anchor="w")

        self.label_estado = tk.Label(
            self, text="", wraplength=460, justify="left", font=("Segoe UI", fuente_base),
            bg=colores["bg"], fg=colores["fg"]
        )
        self.label_estado.pack(anchor="w", pady=(0, 10))

        self.frame_acciones = tk.Frame(self, bg=colores["bg"])
        self.frame_acciones.pack(anchor="w", pady=(0, 14))

        fila_historial = tk.Frame(self, bg=colores["bg"])
        fila_historial.pack(anchor="w", fill="x")
        tk.Label(
            fila_historial, text="Historial de esta sesion:", font=("Segoe UI", fuente_base - 1, "bold"),
            bg=colores["bg"], fg=colores["sub"]
        ).pack(side="left")
        tk.Button(
            fila_historial, text="Limpiar", font=("Segoe UI", fuente_base - 2),
            command=self._limpiar_historial
        ).pack(side="left", padx=(10, 0))
        self.label_historial = tk.Label(
            self, text="Todavia no has escaneado nada.", justify="left",
            font=("Segoe UI", fuente_base - 1), bg=colores["bg"], fg=colores["sub"], wraplength=480
        )
        self.label_historial.pack(anchor="w", pady=(4, 0))

        if archivo_inicial and os.path.isfile(archivo_inicial):
            self.ruta_seleccionada = archivo_inicial
            self._mostrar_info_archivo(archivo_inicial)
            self.boton_escanear.config(state="normal")

    def _mostrar_info_archivo(self, ruta):
        nombre = os.path.basename(ruta)
        try:
            tamano = formatear_tamano(os.path.getsize(ruta))
        except OSError:
            tamano = "desconocido"
        tipo = obtener_tipo_archivo(ruta)
        self.label_archivo.config(
            text=f"Nombre: {nombre}\nTamano: {tamano}\nTipo: {tipo}",
            fg=self.colores["fg"]
        )

    def _archivo_soltado(self, event):
        rutas = self.tk.splitlist(event.data)
        if not rutas:
            return
        ruta = rutas[0]
        if not os.path.isfile(ruta):
            return
        self.ruta_seleccionada = ruta
        self.hash_actual = None
        self._mostrar_info_archivo(ruta)
        self.boton_escanear.config(state="normal")
        self.label_estado.config(text="")
        self._limpiar_acciones()

    def _seleccionar_archivo(self):
        ruta = filedialog.askopenfilename(title="Selecciona un archivo para analizar")
        if ruta:
            self.ruta_seleccionada = ruta
            self.hash_actual = None
            self._mostrar_info_archivo(ruta)
            self.boton_escanear.config(state="normal")
            self.label_estado.config(text="")
            self._limpiar_acciones()

    def _limpiar_acciones(self):
        for widget in self.frame_acciones.winfo_children():
            widget.destroy()

    def _iniciar_escaneo(self):
        if not self.ruta_seleccionada:
            return
        if not self.api_key:
            messagebox.showwarning("Falta la API key", "Configura tu API key antes de escanear.")
            return
        self.boton_escanear.config(state="disabled")
        self.label_estado.config(text="Calculando hash y consultando VirusTotal...", fg=self.colores["fg"])
        self._limpiar_acciones()
        hilo = threading.Thread(target=self._escanear_en_segundo_plano, daemon=True)
        hilo.start()

    def _escanear_en_segundo_plano(self):
        try:
            hash_archivo = calcular_sha256(self.ruta_seleccionada)
            self.hash_actual = hash_archivo
            resultado = consultar_virustotal(hash_archivo, self.api_key)
        except requests.exceptions.ConnectionError:
            self._actualizar_resultado_error("No hay conexion a internet. Revisa tu red e intenta de nuevo.")
            return
        except requests.exceptions.Timeout:
            self._actualizar_resultado_error("La consulta tardo demasiado. Intenta de nuevo.")
            return
        except ValueError as e:
            self._actualizar_resultado_error(str(e))
            return
        except OSError:
            self._actualizar_resultado_error("No se pudo leer el archivo seleccionado.")
            return

        self._actualizar_resultado_ok(resultado)

    def _actualizar_resultado_error(self, mensaje):
        self.after(0, lambda: self._mostrar_resultado(mensaje, "#c0392b", "error", None))

    def _actualizar_resultado_ok(self, resultado):
        nombre = os.path.basename(self.ruta_seleccionada)
        if not resultado["encontrado"]:
            texto = "Nadie ha subido antes este archivo a VirusTotal, asi que\nno hay un resultado todavia. No es senal de nada malo,\nsimplemente es un archivo poco comun o nuevo."
            self.after(0, lambda: self._mostrar_resultado(texto, "#c07800", "desconocido", nombre))
        else:
            maliciosos = resultado["maliciosos"]
            sospechosos = resultado["sospechosos"]
            total_alerta = maliciosos + sospechosos
            total_motores = maliciosos + sospechosos + resultado["inofensivos"] + resultado["sin_detectar"]
            if total_alerta > 0:
                texto = f"Cuidado: {total_alerta} de {total_motores} antivirus que usa VirusTotal\ndetectaron este archivo como una posible amenaza.\nLo mas seguro es eliminarlo."
                self.after(0, lambda: self._mostrar_resultado(texto, "#c0392b", "amenaza", nombre))
            else:
                texto = f"Este archivo se ve limpio: ninguno de los {total_motores} antivirus\nde VirusTotal lo marco como amenaza."
                self.after(0, lambda: self._mostrar_resultado(texto, "#1e8449", "limpio", nombre))

    def _mostrar_resultado(self, texto, color, tipo, nombre):
        self.label_estado.config(text=texto, fg=color)
        self.boton_escanear.config(state="normal")
        self.tipo_resultado_actual = tipo
        self._limpiar_acciones()

        if self.hash_actual:
            tk.Button(
                self.frame_acciones, text="Copiar hash", width=14,
                command=self._copiar_hash
            ).pack(side="left")
            tk.Button(
                self.frame_acciones, text="Copiar informe", width=14,
                command=self._copiar_informe
            ).pack(side="left", padx=(10, 0))
            tk.Button(
                self.frame_acciones, text="Exportar informe", width=15,
                command=self._exportar_informe
            ).pack(side="left", padx=(10, 0))
            if tipo in ("amenaza", "limpio"):
                tk.Button(
                    self.frame_acciones, text="Ver analisis completo", width=18,
                    command=self._abrir_analisis_completo
                ).pack(side="left", padx=(10, 0))

        if tipo == "amenaza":
            tk.Button(
                self.frame_acciones, text="Eliminar archivo", width=16,
                bg="#c0392b", fg="white", command=self._eliminar_archivo
            ).pack(side="left", padx=(10, 0))
            tk.Button(
                self.frame_acciones, text="Mantener (no recomendado)", width=22,
                command=self._confirmar_mantener
            ).pack(side="left", padx=(10, 0))

        if nombre:
            iconos = {"amenaza": "🔴", "limpio": "🟢", "desconocido": "⚪"}
            etiquetas = {"amenaza": "amenaza detectada", "limpio": "sin amenazas", "desconocido": "sin datos"}
            icono = iconos.get(tipo, "⚪")
            self.historial.insert(0, f"{icono} {nombre} - {etiquetas.get(tipo, tipo)}")
            self.historial = self.historial[:5]
            self.label_historial.config(text="\n".join(self.historial))

    def _limpiar_historial(self):
        if not self.historial:
            return
        confirmar = messagebox.askyesno("Limpiar historial", "Deseas eliminar el historial de esta sesion?")
        if confirmar:
            self.historial = []
            self.label_historial.config(text="Todavia no has escaneado nada.")

    def _abrir_analisis_completo(self):
        if self.hash_actual:
            webbrowser.open(f"https://www.virustotal.com/gui/file/{self.hash_actual}")

    def _construir_texto_informe(self):
        nombre = os.path.basename(self.ruta_seleccionada)
        try:
            tamano = formatear_tamano(os.path.getsize(self.ruta_seleccionada))
        except OSError:
            tamano = "desconocido"
        tipo = obtener_tipo_archivo(self.ruta_seleccionada)
        estados = {"amenaza": "Amenaza detectada", "limpio": "Sin detecciones", "desconocido": "Sin datos disponibles"}
        estado = estados.get(self.tipo_resultado_actual, "Sin datos disponibles")
        return (
            f"{APP_NAME} v{VERSION}\n\n"
            f"Archivo: {nombre}\n"
            f"Tamano: {tamano}\n"
            f"Tipo: {tipo}\n\n"
            f"SHA-256:\n{self.hash_actual}\n\n"
            f"Estado:\n{estado}"
        )

    def _copiar_informe(self):
        if not self.hash_actual or not self.ruta_seleccionada:
            return
        self.clipboard_clear()
        self.clipboard_append(self._construir_texto_informe())
        messagebox.showinfo("Copiado", "El informe se copio al portapapeles.")

    def _exportar_informe(self):
        if not self.hash_actual or not self.ruta_seleccionada:
            return
        nombre_sugerido = os.path.splitext(os.path.basename(self.ruta_seleccionada))[0] + "_informe.txt"
        ruta_destino = filedialog.asksaveasfilename(
            title="Guardar informe", defaultextension=".txt",
            initialfile=nombre_sugerido, filetypes=[("Archivo de texto", "*.txt")]
        )
        if not ruta_destino:
            return
        try:
            with open(ruta_destino, "w", encoding="utf-8") as f:
                f.write(self._construir_texto_informe())
            messagebox.showinfo("Guardado", "El informe se guardo correctamente.")
        except OSError as e:
            messagebox.showerror("No se pudo guardar", f"No fue posible guardar el informe:\n{e}")

    def _copiar_hash(self):
        if self.hash_actual:
            self.clipboard_clear()
            self.clipboard_append(self.hash_actual)
            messagebox.showinfo("Copiado", "El hash SHA-256 del archivo se copio al portapapeles.")

    def _confirmar_mantener(self):
        confirmar = messagebox.askyesno(
            "Confirmar",
            "VirusTotal detecto este archivo como posible amenaza.\n\nSi continuas, confirmas que entiendes el riesgo y decides\nconservarlo bajo tu propia responsabilidad.\n\nEsta seguro de que quiere mantenerlo?"
        )
        if confirmar:
            self.label_estado.config(text=self.label_estado.cget("text") + "\n\nMantenido por decision del usuario.")
            self._limpiar_acciones()

    def _eliminar_archivo(self):
        confirmar = messagebox.askyesno(
            "Eliminar archivo",
            f"Se eliminara este archivo de forma permanente:\n\n{self.ruta_seleccionada}\n\nEsta accion no se puede deshacer. Continuar?"
        )
        if not confirmar:
            return
        try:
            os.remove(self.ruta_seleccionada)
            self.label_archivo.config(text="Archivo eliminado.", fg="#1e8449")
            self.label_estado.config(text="El archivo fue eliminado correctamente.", fg="#1e8449")
            self.boton_escanear.config(state="disabled")
            self.ruta_seleccionada = None
            self._limpiar_acciones()
        except OSError as e:
            messagebox.showerror("No se pudo eliminar", f"No fue posible eliminar el archivo:\n{e}")


class PantallaBuscarHash(tk.Frame):
    def __init__(self, master, api_key, tema, tamano):
        colores = TEMAS[tema]
        fuente_base = TAMANOS_FUENTE[tamano]
        super().__init__(master, padx=25, pady=25, bg=colores["bg"])
        self.api_key = api_key
        self.colores = colores

        tk.Label(
            self, text="Buscar por SHA-256", font=("Segoe UI", fuente_base + 2, "bold"),
            bg=colores["bg"], fg=colores["fg"]
        ).pack(pady=(0, 4), anchor="w")

        tk.Label(
            self, text="Consulta un hash sin necesidad de tener el archivo.",
            fg=colores["sub"], bg=colores["bg"], font=("Segoe UI", fuente_base)
        ).pack(pady=(0, 14), anchor="w")

        self.entry_hash = tk.Entry(self, width=64)
        estilizar_entry(self.entry_hash, colores)
        self.entry_hash.pack(pady=(0, 10), anchor="w")

        self.boton_consultar = crear_boton(self, "Consultar", self._consultar, colores, ancho=14, primario=True)
        self.boton_consultar.pack(pady=(0, 14), anchor="w")

        self.label_estado = tk.Label(
            self, text="", wraplength=460, justify="left", font=("Segoe UI", fuente_base),
            bg=colores["bg"], fg=colores["fg"]
        )
        self.label_estado.pack(anchor="w")

    def _consultar(self):
        hash_archivo = self.entry_hash.get().strip().lower()
        if len(hash_archivo) != 64:
            messagebox.showwarning("Hash invalido", "Un hash SHA-256 debe tener 64 caracteres.")
            return
        if not self.api_key:
            messagebox.showwarning("Falta la API key", "Configura tu API key antes de consultar.")
            return
        self.boton_consultar.config(state="disabled")
        self.label_estado.config(text="Consultando VirusTotal...", fg=self.colores["fg"])
        hilo = threading.Thread(target=self._consultar_en_segundo_plano, args=(hash_archivo,), daemon=True)
        hilo.start()

    def _consultar_en_segundo_plano(self, hash_archivo):
        try:
            resultado = consultar_virustotal(hash_archivo, self.api_key)
        except requests.exceptions.ConnectionError:
            self.after(0, lambda: self._mostrar("No hay conexion a internet.", "#c0392b"))
            return
        except requests.exceptions.Timeout:
            self.after(0, lambda: self._mostrar("La consulta tardo demasiado.", "#c0392b"))
            return
        except ValueError as e:
            self.after(0, lambda: self._mostrar(str(e), "#c0392b"))
            return

        if not resultado["encontrado"]:
            self.after(0, lambda: self._mostrar("Ese hash no tiene informacion en VirusTotal.", "#c07800"))
            return

        total_alerta = resultado["maliciosos"] + resultado["sospechosos"]
        total_motores = total_alerta + resultado["inofensivos"] + resultado["sin_detectar"]
        if total_alerta > 0:
            texto = f"{total_alerta} de {total_motores} antivirus marcaron este hash como amenaza."
            self.after(0, lambda: self._mostrar(texto, "#c0392b"))
        else:
            texto = f"Ninguno de los {total_motores} antivirus marco este hash como amenaza."
            self.after(0, lambda: self._mostrar(texto, "#1e8449"))

    def _mostrar(self, texto, color):
        self.label_estado.config(text=texto, fg=color)
        self.boton_consultar.config(state="normal")


class PantallaAnalizarURL(tk.Frame):
    def __init__(self, master, api_key, tema, tamano):
        colores = TEMAS[tema]
        fuente_base = TAMANOS_FUENTE[tamano]
        super().__init__(master, padx=25, pady=25, bg=colores["bg"])
        self.api_key = api_key
        self.colores = colores
        self.id_url_actual = None

        tk.Label(
            self, text="Analizar una URL", font=("Segoe UI", fuente_base + 2, "bold"),
            bg=colores["bg"], fg=colores["fg"]
        ).pack(pady=(0, 4), anchor="w")

        tk.Label(
            self, text="Se envia la direccion a VirusTotal para revisarla, sin descargar nada.",
            fg=colores["sub"], bg=colores["bg"], font=("Segoe UI", fuente_base)
        ).pack(pady=(0, 14), anchor="w")

        self.entry_url = tk.Entry(self, width=64)
        estilizar_entry(self.entry_url, colores)
        self.entry_url.pack(pady=(0, 10), anchor="w")

        self.boton_analizar = crear_boton(self, "Analizar", self._analizar, colores, ancho=14, primario=True)
        self.boton_analizar.pack(pady=(0, 14), anchor="w")

        self.label_estado = tk.Label(
            self, text="", wraplength=460, justify="left", font=("Segoe UI", fuente_base),
            bg=colores["bg"], fg=colores["fg"]
        )
        self.label_estado.pack(anchor="w", pady=(0, 10))

        self.frame_acciones = tk.Frame(self, bg=colores["bg"])
        self.frame_acciones.pack(anchor="w")

    def _analizar(self):
        url = self.entry_url.get().strip()
        if not url.startswith(("http://", "https://")):
            messagebox.showwarning("URL invalida", "La direccion debe empezar con http:// o https://")
            return
        if not self.api_key:
            messagebox.showwarning("Falta la API key", "Configura tu API key antes de analizar.")
            return
        self.boton_analizar.config(state="disabled")
        self.label_estado.config(text="Consultando VirusTotal, esto puede tardar unos segundos...", fg=self.colores["fg"])
        for widget in self.frame_acciones.winfo_children():
            widget.destroy()
        hilo = threading.Thread(target=self._analizar_en_segundo_plano, args=(url,), daemon=True)
        hilo.start()

    def _analizar_en_segundo_plano(self, url):
        try:
            resultado = consultar_url_virustotal(url, self.api_key)
        except requests.exceptions.ConnectionError:
            self.after(0, lambda: self._mostrar("No hay conexion a internet.", "#c0392b", None))
            return
        except requests.exceptions.Timeout:
            self.after(0, lambda: self._mostrar("La consulta tardo demasiado.", "#c0392b", None))
            return
        except ValueError as e:
            self.after(0, lambda: self._mostrar(str(e), "#c0392b", None))
            return

        if not resultado["encontrado"]:
            self.after(0, lambda: self._mostrar(
                "El analisis sigue en proceso. Intenta consultarla de nuevo en un momento.",
                "#c07800", resultado["id_url"]
            ))
            return

        total_alerta = resultado["maliciosos"] + resultado["sospechosos"]
        total_motores = total_alerta + resultado["inofensivos"] + resultado["sin_detectar"]
        if total_alerta > 0:
            texto = f"Cuidado: {total_alerta} de {total_motores} motores marcaron esta URL como amenaza."
            self.after(0, lambda: self._mostrar(texto, "#c0392b", resultado["id_url"]))
        else:
            texto = f"Ninguno de los {total_motores} motores marco esta URL como amenaza."
            self.after(0, lambda: self._mostrar(texto, "#1e8449", resultado["id_url"]))

    def _mostrar(self, texto, color, id_url):
        self.label_estado.config(text=texto, fg=color)
        self.boton_analizar.config(state="normal")
        self.id_url_actual = id_url
        for widget in self.frame_acciones.winfo_children():
            widget.destroy()
        if id_url:
            tk.Button(
                self.frame_acciones, text="Ver analisis completo", width=18,
                command=self._abrir_analisis
            ).pack(side="left")

    def _abrir_analisis(self):
        if self.id_url_actual:
            webbrowser.open(f"https://www.virustotal.com/gui/url/{self.id_url_actual}")


def activar_menu_contextual():
    if os.name != "nt":
        return False, "Esta funcion solo esta disponible en Windows."
    try:
        import winreg
    except ImportError:
        return False, "No se pudo acceder al registro de Windows."

    ruta_exe = obtener_ruta_ejecutable_actual()
    comando = f'"{ruta_exe}" "%1"'
    clave_shell = r"Software\Classes\*\shell\AnalizaArch"
    try:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, clave_shell) as clave:
            winreg.SetValue(clave, "", winreg.REG_SZ, "Analizar con AnalizaArch")
            if getattr(sys, "frozen", False):
                winreg.SetValueEx(clave, "Icon", 0, winreg.REG_SZ, ruta_exe)
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, clave_shell + r"\command") as clave:
            winreg.SetValue(clave, "", winreg.REG_SZ, comando)
        return True, "Ya puedes dar clic derecho en cualquier archivo y elegir 'Analizar con AnalizaArch'."
    except OSError as e:
        return False, f"No se pudo agregar la opcion al menu contextual:\n{e}"


def quitar_menu_contextual():
    if os.name != "nt":
        return False, "Esta funcion solo esta disponible en Windows."
    try:
        import winreg
    except ImportError:
        return False, "No se pudo acceder al registro de Windows."

    clave_shell = r"Software\Classes\*\shell\AnalizaArch"
    try:
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, clave_shell + r"\command")
        except FileNotFoundError:
            pass
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, clave_shell)
        except FileNotFoundError:
            pass
        return True, "La opcion del menu contextual fue eliminada."
    except OSError as e:
        return False, f"No se pudo quitar la opcion del menu contextual:\n{e}"


class VentanaPrincipal(BaseVentana):
    def __init__(self, archivo_inicial=None):
        super().__init__()
        self.archivo_inicial = archivo_inicial
        self.config_datos = cargar_config()
        self.title(f"{APP_NAME} v{VERSION}")
        self.geometry("580x520")
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self._cerrar)

        self.icono = obtener_icono()
        if self.icono:
            self.iconphoto(True, self.icono)

        if not self.config_datos["api_key"]:
            self._mostrar_configuracion(permitir_cancelar=False)
        else:
            if self.archivo_inicial:
                self._ir_a_escanear(archivo_inicial=self.archivo_inicial)
            else:
                self._mostrar_app_principal()

    def _cerrar(self):
        self.destroy()

    def _aplicar_fondo_ventana(self):
        colores = TEMAS[self.config_datos["tema"]]
        self.configure(bg=colores["bg"])

    def _construir_barra_superior(self):
        colores = TEMAS[self.config_datos["tema"]]
        barra = tk.Frame(self, bg=colores["bg_panel"], height=44)
        barra.pack(side="top", fill="x")
        barra.pack_propagate(False)

        contenedor_titulo = tk.Frame(barra, bg=colores["bg_panel"])
        contenedor_titulo.pack(side="left", padx=12)
        if self.icono:
            tk.Label(contenedor_titulo, image=self.icono, bg=colores["bg_panel"]).pack(side="left", padx=(0, 8))
        tk.Label(
            contenedor_titulo, text=APP_NAME, font=("Segoe UI", 11, "bold"),
            bg=colores["bg_panel"], fg=colores["fg"]
        ).pack(side="left")

        boton_menu = crear_boton(
            barra, "☰", self._alternar_panel_menu, colores, ancho=3, font=("Segoe UI", 13)
        )
        boton_menu.pack(side="right", padx=8)

    def _alternar_panel_menu(self):
        if getattr(self, "panel_menu", None) and self.panel_menu.winfo_exists():
            self._cerrar_panel_menu()
            return

        colores = TEMAS[self.config_datos["tema"]]
        opciones = [
            ("🔍 Escanear", self._ir_a_escanear),
            ("🔎 Buscar por hash", self._ir_a_buscar_hash),
            ("🌐 Analizar URL", self._ir_a_analizar_url),
            (None, None),
            ("⚙ Preferencias", self._ir_a_preferencias),
            ("🔑 Cambiar API key", self._mostrar_configuracion),
            ("🖱 Activar clic derecho", self._activar_menu_contextual),
            ("🖱 Quitar clic derecho", self._quitar_menu_contextual),
            (None, None),
            ("🗕 Minimizar a bandeja", self._minimizar_a_bandeja),
            ("ℹ Info", self._mostrar_info),
            ("☕ Donacion", lambda: webbrowser.open(DONACION_URL)),
            ("✕ Cerrar", self._cerrar),
        ]

        self.panel_menu = tk.Toplevel(self)
        self.panel_menu.overrideredirect(True)
        self.panel_menu.attributes("-topmost", True)
        self.panel_menu.configure(bg=colores["bg_panel"])

        ancho = 230
        alto = len(opciones) * 32 + 12
        x = self.winfo_rootx() + self.winfo_width() - ancho - 8
        y = self.winfo_rooty() + 44
        self.panel_menu.geometry(f"{ancho}x{alto}+{x}+{y}")

        for etiqueta, accion in opciones:
            if etiqueta is None:
                tk.Frame(self.panel_menu, bg=colores["sub"], height=1).pack(fill="x", padx=10, pady=4)
                continue
            boton = crear_boton(
                self.panel_menu, etiqueta, lambda a=accion: self._ejecutar_desde_panel(a), colores,
                font=("Segoe UI", 10), anchor="w", padx=12
            )
            boton.pack(fill="x")

        self.panel_menu.bind("<FocusOut>", lambda e: self._cerrar_panel_menu())
        self.panel_menu.focus_force()

    def _cerrar_panel_menu(self):
        if getattr(self, "panel_menu", None) and self.panel_menu.winfo_exists():
            self.panel_menu.destroy()
        self.panel_menu = None

    def _ejecutar_desde_panel(self, accion):
        self._cerrar_panel_menu()
        accion()

    def _minimizar_a_bandeja(self):
        if not BANDEJA_DISPONIBLE:
            messagebox.showinfo(
                "Funcion no disponible",
                "Para minimizar a la bandeja del sistema instala:\n\npip install pystray pillow"
            )
            return
        self.withdraw()
        imagen = PILImage.open(io.BytesIO(base64.b64decode(ICONO_B64)))
        menu_bandeja = pystray.Menu(
            pystray.MenuItem("Abrir", self._restaurar_desde_bandeja, default=True),
            pystray.MenuItem("Salir", self._salir_desde_bandeja),
        )
        self.icono_bandeja = pystray.Icon(APP_NAME, imagen, APP_NAME, menu_bandeja)
        hilo = threading.Thread(target=self.icono_bandeja.run, daemon=True)
        hilo.start()

    def _restaurar_desde_bandeja(self, icon, item=None):
        icon.stop()
        self.after(0, self.deiconify)

    def _salir_desde_bandeja(self, icon, item=None):
        icon.stop()
        self.after(0, self._cerrar)

    def _activar_menu_contextual(self):
        exito, mensaje = activar_menu_contextual()
        if exito:
            messagebox.showinfo("Listo", mensaje)
        else:
            messagebox.showerror("No se pudo activar", mensaje)

    def _quitar_menu_contextual(self):
        exito, mensaje = quitar_menu_contextual()
        if exito:
            messagebox.showinfo("Listo", mensaje)
        else:
            messagebox.showerror("No se pudo quitar", mensaje)

    def _mostrar_configuracion(self, permitir_cancelar=True):
        for widget in self.winfo_children():
            widget.destroy()
        self._aplicar_fondo_ventana()
        key_actual = self.config_datos["api_key"]
        cancelar = self._mostrar_app_principal if (permitir_cancelar and key_actual) else None
        pantalla = PantallaConfiguracion(
            self, self.config_datos["tema"], self.config_datos["tamano"],
            self._api_key_lista, on_cancelar=cancelar, key_actual=key_actual
        )
        pantalla.pack(fill="both", expand=True)

    def _api_key_lista(self, key):
        era_primera_vez = self.config_datos.get("primera_vez", True) and not self.config_datos["api_key"]
        self.config_datos["api_key"] = key
        self.config_datos["primera_vez"] = False
        guardar_config(self.config_datos)
        self._mostrar_app_principal()
        if era_primera_vez:
            messagebox.showinfo(
                "Listo",
                "Tu API key quedo guardada.\n\nYa puedes escanear tu primer archivo desde el menu 'Escanear'."
            )

    def _ir_a_preferencias(self):
        for widget in self.winfo_children():
            widget.destroy()
        self._aplicar_fondo_ventana()
        pantalla = PantallaPreferencias(
            self, self.config_datos["tema"], self.config_datos["tamano"],
            self._guardar_preferencias, self._mostrar_app_principal
        )
        pantalla.pack(fill="both", expand=True)

    def _guardar_preferencias(self, tema, tamano):
        self.config_datos["tema"] = tema
        self.config_datos["tamano"] = tamano
        guardar_config(self.config_datos)
        self._mostrar_app_principal()

    def _mostrar_app_principal(self):
        for widget in self.winfo_children():
            widget.destroy()
        self._aplicar_fondo_ventana()
        self._construir_barra_superior()
        colores = TEMAS[self.config_datos["tema"]]
        fuente_base = TAMANOS_FUENTE[self.config_datos["tamano"]]

        contenido = tk.Frame(self, bg=colores["bg"])
        contenido.pack(expand=True)

        if self.icono:
            tk.Label(contenido, image=self.icono, bg=colores["bg"]).pack(pady=(30, 10))

        tk.Label(
            contenido, text=APP_NAME, font=("Segoe UI", fuente_base + 6, "bold"),
            bg=colores["bg"], fg=colores["fg"]
        ).pack()

        tk.Label(
            contenido, text="Analiza archivos, hashes y URLs con VirusTotal",
            font=("Segoe UI", fuente_base), bg=colores["bg"], fg=colores["sub"]
        ).pack(pady=(2, 28))

        for etiqueta, accion in [
            ("🔍  Escanear un archivo", self._ir_a_escanear),
            ("🔎  Buscar por hash", self._ir_a_buscar_hash),
            ("🌐  Analizar una URL", self._ir_a_analizar_url),
        ]:
            boton = crear_boton(
                contenido, etiqueta, accion, colores, ancho=28, primario=True,
                font=("Segoe UI", fuente_base), anchor="w", padx=14, pady=8
            )
            boton.pack(pady=4)

        tk.Label(
            contenido, text="Ligero • Bajo demanda • Sin procesos en segundo plano",
            font=("Segoe UI", fuente_base - 2), bg=colores["bg"], fg=colores["sub"]
        ).pack(pady=(28, 0))

    def _ir_a_escanear(self, archivo_inicial=None):
        for widget in self.winfo_children():
            widget.destroy()
        self._aplicar_fondo_ventana()
        self._construir_barra_superior()
        pantalla = PantallaEscaneo(
            self, self.config_datos["api_key"], self.config_datos["tema"], self.config_datos["tamano"],
            archivo_inicial=archivo_inicial
        )
        pantalla.pack(fill="both", expand=True)

    def _ir_a_buscar_hash(self):
        for widget in self.winfo_children():
            widget.destroy()
        self._aplicar_fondo_ventana()
        self._construir_barra_superior()
        pantalla = PantallaBuscarHash(
            self, self.config_datos["api_key"], self.config_datos["tema"], self.config_datos["tamano"]
        )
        pantalla.pack(fill="both", expand=True)

    def _ir_a_analizar_url(self):
        for widget in self.winfo_children():
            widget.destroy()
        self._aplicar_fondo_ventana()
        self._construir_barra_superior()
        pantalla = PantallaAnalizarURL(
            self, self.config_datos["api_key"], self.config_datos["tema"], self.config_datos["tamano"]
        )
        pantalla.pack(fill="both", expand=True)

    def _mostrar_info(self):
        messagebox.showinfo(
            f"Info - {APP_NAME} v{VERSION}",
            f"{APP_NAME} - version {VERSION}\n\n"
            "Herramienta gratuita que usa la API de VirusTotal para revisar si un archivo ha sido detectado como amenaza por otros antivirus.\n\n"
            "No es un antivirus en tiempo real ni escanea tu PC completa: solo analiza el archivo que tu selecciones.\n\n"
            "No se garantiza la deteccion del 100% de las amenazas; el resultado depende directamente de lo que reporte VirusTotal.\n\n"
            "Tus archivos no se guardan en ningun lado; unicamente se consulta su huella digital (hash) en VirusTotal.\n\n"
            "Hecho de forma independiente por un desarrollador en Mexico.\n"
            "Si te sirvio, puedes apoyar el proyecto desde el menu 'Donacion'."
        )


if __name__ == "__main__":
    archivo_desde_argumentos = sys.argv[1] if len(sys.argv) > 1 else None
    app = VentanaPrincipal(archivo_inicial=archivo_desde_argumentos)
    app.mainloop()
