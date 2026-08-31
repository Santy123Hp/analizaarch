import tkinter as tk
from tkinter import messagebox, filedialog
import webbrowser
import os
import json
import hashlib
import threading
import base64
import requests

APP_NAME = "AnalizaArch"
VERSION = "0.3"

CONFIG_FILE = os.path.join(os.path.expanduser("~"), ".analizaarch_config.json")
VT_APIKEY_URL = "https://www.virustotal.com/gui/my-apikey"
VT_API_URL = "https://www.virustotal.com/api/v3/files/{hash}"
DONACION_URL = "https://github.com/Santy123Hp/analizaarch?tab=readme-ov-file"

ICONO_B64 = "iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAACZklEQVR4nO2bPU4DMRCFH4h+b5AjUKSgokmfu+QsuQt9GioKihwhN8gJoEBB1sb2zr+9ij8JiSTs2u/N2PGaMTAYDAYNmTbvPy3bf2rRaE309fIZ2qfQxlLh0+bt7vPr5Sv5PcYI90bm0c4Jn5Ma8ffazwy3Gy9Fm4p3VpjeUBJtKl5Zob6JVvS03eP6/cG6xtIM8YXaFJ+2+7v3uEYA+iHCusAi2lSisoL0Rx7RpuKdFcUPI6NNxSMrFg3oQfgcqRE5A14sOhQhutSeZIikqAyIFl7rg9QItgE9iM4hzYpnj854cj7uTO+3KgNu4s/HnZkRqzEgJ9jCiNUYUOL1cFJdvwoDSlHWigdWYID1pDenawNq4i2iD3RsQIR4oFMDosQDnRpQwlo80KEBnjN+jq4M8J7xc7gZwBUTOe5TzA1Il6dUE1qJBwQGlB41S+tyTVpLxHP3BYoG3LaP5vtqJaSR8p70atthgHAIlFwudbok0nrSk+wKVQ3gZkGNudiIcb8UfUAxCXKzAABpcpSKl+4JLhogyQKKCdzruFCiDyi/Bmuuc8VoxGu2xkkGSOcCqijr73pq9AGDhZD2HxOt2ycb4JUFLaMPGC2Fl6JwE/l6OP3/pO97tUsh7GlwLtZ7jU+FZUBtGETPBbn2uOkPdLYf0AL+02AHWWAVfWBkgL5KrFRBElkiI40+YFQhkiPtbHSRFAdVoSS3jsijTE4TfcAxA3IsZUWLZbVZqay0LlhSKntDG32gg1phCV3UCuewKpEv4VE673JewDIrvA9PjBMjXjfO8ZBnhnL0dGqsOa3PDQ4GD84vttWG54T+OmwAAAAASUVORK5CYII="

TEMAS = {
    "claro": {"bg": "#f4f4f4", "fg": "#1a1a1a", "bg_panel": "#ffffff", "sub": "#555555"},
    "oscuro": {"bg": "#1e1e1e", "fg": "#eaeaea", "bg_panel": "#2b2b2b", "sub": "#9a9a9a"},
}

TAMANOS_FUENTE = {"pequeno": 9, "mediano": 11, "grande": 14}

CONFIG_POR_DEFECTO = {"api_key": "", "tema": "claro", "tamano": "mediano", "primera_vez": True}


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
    def __init__(self, master, api_key, tema, tamano):
        colores = TEMAS[tema]
        fuente_base = TAMANOS_FUENTE[tamano]
        super().__init__(master, padx=25, pady=25, bg=colores["bg"])
        self.api_key = api_key
        self.colores = colores
        self.fuente_base = fuente_base
        self.ruta_seleccionada = None
        self.hash_actual = None
        self.historial = []

        tk.Label(
            self, text="Analizar un archivo", font=("Segoe UI", fuente_base + 2, "bold"),
            bg=colores["bg"], fg=colores["fg"]
        ).pack(pady=(0, 4), anchor="w")

        tk.Label(
            self, text="Selecciona un archivo y se revisara contra la base de VirusTotal.",
            fg=colores["sub"], bg=colores["bg"], font=("Segoe UI", fuente_base)
        ).pack(pady=(0, 16), anchor="w")

        tk.Button(
            self, text="Seleccionar archivo...", command=self._seleccionar_archivo
        ).pack(pady=(0, 8), anchor="w")

        self.label_archivo = tk.Label(self, text="Ningun archivo seleccionado", fg="gray", bg=colores["bg"], font=("Segoe UI", fuente_base))
        self.label_archivo.pack(pady=(0, 16), anchor="w")

        self.boton_escanear = tk.Button(
            self, text="Escanear", state="disabled", width=14, command=self._iniciar_escaneo
        )
        self.boton_escanear.pack(pady=(0, 14), anchor="w")

        self.label_estado = tk.Label(
            self, text="", wraplength=460, justify="left", font=("Segoe UI", fuente_base),
            bg=colores["bg"], fg=colores["fg"]
        )
        self.label_estado.pack(anchor="w", pady=(0, 10))

        self.frame_acciones = tk.Frame(self, bg=colores["bg"])
        self.frame_acciones.pack(anchor="w", pady=(0, 14))

        tk.Label(
            self, text="Historial de esta sesion:", font=("Segoe UI", fuente_base - 1, "bold"),
            bg=colores["bg"], fg=colores["sub"]
        ).pack(anchor="w")
        self.label_historial = tk.Label(
            self, text="Todavia no has escaneado nada.", justify="left",
            font=("Segoe UI", fuente_base - 1), bg=colores["bg"], fg=colores["sub"], wraplength=480
        )
        self.label_historial.pack(anchor="w", pady=(4, 0))

    def _seleccionar_archivo(self):
        ruta = filedialog.askopenfilename(title="Selecciona un archivo para analizar")
        if ruta:
            self.ruta_seleccionada = ruta
            self.hash_actual = None
            nombre = os.path.basename(ruta)
            self.label_archivo.config(text=f"Seleccionado: {nombre}", fg=self.colores["fg"])
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
            if total_alerta > 0:
                texto = f"Cuidado: {total_alerta} de los antivirus que usa VirusTotal\ndetectaron este archivo como una posible amenaza.\nLo mas seguro es eliminarlo."
                self.after(0, lambda: self._mostrar_resultado(texto, "#c0392b", "amenaza", nombre))
            else:
                texto = "Este archivo se ve limpio: ninguno de los antivirus\nde VirusTotal lo marco como amenaza."
                self.after(0, lambda: self._mostrar_resultado(texto, "#1e8449", "limpio", nombre))

    def _mostrar_resultado(self, texto, color, tipo, nombre):
        self.label_estado.config(text=texto, fg=color)
        self.boton_escanear.config(state="normal")
        self._limpiar_acciones()

        if self.hash_actual:
            tk.Button(
                self.frame_acciones, text="Copiar hash del archivo", width=20,
                command=self._copiar_hash
            ).pack(side="left")

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
            etiquetas = {"amenaza": "amenaza detectada", "limpio": "sin amenazas", "desconocido": "sin datos"}
            self.historial.insert(0, f"{nombre} - {etiquetas.get(tipo, tipo)}")
            self.historial = self.historial[:5]
            self.label_historial.config(text="\n".join(self.historial))

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


class VentanaPrincipal(tk.Tk):
    def __init__(self):
        super().__init__()
        self.config_datos = cargar_config()
        self.title(f"{APP_NAME} v{VERSION}")
        self.geometry("580x480")
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self._cerrar)

        self.icono = obtener_icono()
        if self.icono:
            self.iconphoto(True, self.icono)

        if not self.config_datos["api_key"]:
            self._mostrar_configuracion(permitir_cancelar=False)
        else:
            self._mostrar_app_principal()

    def _cerrar(self):
        self.destroy()

    def _aplicar_fondo_ventana(self):
        colores = TEMAS[self.config_datos["tema"]]
        self.configure(bg=colores["bg"])

    def _construir_menu(self):
        menubar = tk.Menu(self)
        menubar.add_command(label="Escanear", command=self._ir_a_escanear)
        menubar.add_command(label="Info", command=self._mostrar_info)
        menubar.add_command(label="Preferencias", command=self._ir_a_preferencias)
        menubar.add_command(label="Cambiar API key", command=self._mostrar_configuracion)
        menubar.add_command(label="Donacion", command=lambda: webbrowser.open(DONACION_URL))
        menubar.add_command(label="Cerrar", command=self._cerrar)
        self.config(menu=menubar)

    def _mostrar_configuracion(self, permitir_cancelar=True):
        for widget in self.winfo_children():
            widget.destroy()
        self.config(menu=tk.Menu(self))
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
        self.config(menu=tk.Menu(self))
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
        self._construir_menu()
        colores = TEMAS[self.config_datos["tema"]]
        fuente_base = TAMANOS_FUENTE[self.config_datos["tamano"]]
        tk.Label(
            self, text="Selecciona 'Escanear' en el menu para analizar un archivo.",
            font=("Segoe UI", fuente_base), pady=40, bg=colores["bg"], fg=colores["fg"]
        ).pack()

    def _ir_a_escanear(self):
        for widget in self.winfo_children():
            widget.destroy()
        self._aplicar_fondo_ventana()
        self._construir_menu()
        pantalla = PantallaEscaneo(
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
    app = VentanaPrincipal()
    app.mainloop()
