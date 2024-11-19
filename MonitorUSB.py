import os
import sys
import ctypes
import win32file
import win32con
import win32event
import winreg
from datetime import datetime
from tkinter import Tk, messagebox
from PIL import Image, ImageTk
import pystray
from pystray import MenuItem as item

LOG_DIR = r"C:\Driver"
LOG_FILE_PATH = os.path.join(LOG_DIR, "usb_log.html")
MASTER_PASSWORD = "SuaSenha"
connected_devices = {}
tracked_files = {}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Log de Monitoramento USB</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f4f4f4;
            color: #333;
        }}
        h1 {{
            text-align: center;
            padding: 10px;
            background-color: #FD6D10;
            color: white;
        }}
        table {{
            width: 90%;
            margin: 20px auto;
            border-collapse: collapse;
            background: white;
        }}
        th, td {{
            border: 1px solid #ddd;
            text-align: left;
            padding: 8px;
        }}
        th {{
            background-color: #FF8C42;
            color: white;
        }}
        tr:nth-child(even) {{
            background-color: #f9f9f9;
        }}
    </style>
</head>
<body>
    <h1>Log de Monitoramento USB</h1>
    <table>
        <thead>
            <tr>
                <th>Data e Hora</th>
                <th>Evento</th>
                <th>Detalhes</th>
            </tr>
        </thead>
        <tbody>
            {rows}
        </tbody>
    </table>
</body>
</html>"""

def run_as_admin():
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if not is_admin:
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            sys.exit(0)
    except Exception as e:
        sys.exit(1)

def log_message(event, details=""):
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)
    row = f"""
        <tr>
            <td>{datetime.now()}</td>
            <td>{event}</td>
            <td>{details}</td>
        </tr>
    """
    if not os.path.exists(LOG_FILE_PATH):
        with open(LOG_FILE_PATH, "w", encoding="utf-8") as log_file:
            log_file.write(HTML_TEMPLATE.format(rows=row))
    else:
        with open(LOG_FILE_PATH, "r+", encoding="utf-8") as log_file:
            content = log_file.read()
            updated_content = content.replace("<tbody>", f"<tbody>{row}")
            log_file.seek(0)
            log_file.write(updated_content)

def snapshot_usb(drive):
    try:
        files = set()
        for root, _, filenames in os.walk(drive):
            for filename in filenames:
                full_path = os.path.join(root, filename)
                files.add(full_path)
        return files
    except Exception as e:
        log_message("Erro", f"Erro ao capturar snapshot do dispositivo {drive}: {e}")
        return set()

def monitor_usb():
    global connected_devices, tracked_files
    log_message("Sistema", "Iniciando monitoramento de dispositivos USB...")
    try:
        while True:
            drives = win32file.GetLogicalDrives()
            for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                drive = f"{letter}:\\"
                if win32file.GetDriveType(drive) == win32con.DRIVE_REMOVABLE:
                    if drive not in connected_devices:
                        connected_devices[drive] = True
                        tracked_files[drive] = snapshot_usb(drive)
                        log_message("Novo Dispositivo Detectado", f"Drive {drive}")
                        monitor_file_copies(drive)
    except KeyboardInterrupt:
        log_message("Sistema", "Monitoramento encerrado.")

def monitor_file_copies(drive):
    global tracked_files
    notification = win32file.FindFirstChangeNotification(
        drive, True, win32con.FILE_NOTIFY_CHANGE_FILE_NAME | win32con.FILE_NOTIFY_CHANGE_SIZE
    )
    try:
        while True:
            result = win32event.WaitForSingleObject(notification, 500)
            if result == win32con.WAIT_OBJECT_0:
                detect_copied_files(drive)
                win32file.FindNextChangeNotification(notification)
    except Exception as e:
        log_message("Erro", f"Erro ao monitorar cópias de arquivos: {e}")

def detect_copied_files(drive):
    global tracked_files
    try:
        current_files = snapshot_usb(drive)
        new_files = current_files - tracked_files[drive]
        for file in new_files:
            log_message("Arquivo Copiado", f"Origem: Sistema Local, Destino: {file}")
        tracked_files[drive] = current_files
    except Exception as e:
        log_message("Erro", f"Erro ao detectar arquivos copiados: {e}")

def open_log_file():
    os.startfile(LOG_FILE_PATH)

def exit_application(icon, item):
    icon.stop()
    sys.exit()

def setup_tray_icon():
    image = Image.new("RGBA", (64, 64), (255, 105, 0))  # Cor da imagem para o ícone.
    icon = pystray.Icon(
        "USBMonitor",
        image,
        "Monitoramento USB",
        menu=pystray.Menu(
            item("Abrir Log", lambda: open_log_file()),
            item("Sair", lambda icon, item: exit_application(icon, item))
        )
    )
    return icon

def add_to_startup():
    script_path = os.path.abspath(sys.argv[0])
    key = r"Software\Microsoft\Windows\CurrentVersion\Run"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_SET_VALUE) as reg_key:
            winreg.SetValueEx(reg_key, "USBMonitor", 0, winreg.REG_SZ, script_path)
        log_message("Sistema", "Adicionado à inicialização do Windows.")
    except Exception as e:
        log_message("Erro", f"Erro ao adicionar à inicialização: {e}")

# Início do Script
run_as_admin()
add_to_startup()

# Configuração do ícone da bandeja
tray_icon = setup_tray_icon()

# Inicia o monitoramento em segundo plano
from threading import Thread
Thread(target=monitor_usb, daemon=True).start()

# Exibe o ícone na bandeja
tray_icon.run()
