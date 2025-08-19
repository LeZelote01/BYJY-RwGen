import ctypes
import time
import winreg
import os
import threading
from datetime import datetime, timedelta

class UserActivityMonitor:
    def __init__(self):
        self.user_active = False
        self.last_activity_time = datetime.now()
        self.monitor_thread = None
        self.running = False
        
        # Seuil d'inactivité (5 minutes)
        self.inactivity_threshold = 300
        
    def start(self):
        if self.running:
            return
            
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
    
    def stop(self):
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
    
    def _monitor(self):
        while self.running:
            # Vérifier l'activité de la souris
            mouse_active = self.check_mouse_activity()
            
            # Vérifier l'activité du clavier
            keyboard_active = self.check_keyboard_activity()
            
            # Vérifier les processus actifs
            foreground_active = self.check_foreground_process()
            
            # Mettre à jour l'état
            current_activity = mouse_active or keyboard_active or foreground_active
            if current_activity:
                self.last_activity_time = datetime.now()
                self.user_active = True
            else:
                # Vérifier l'inactivité prolongée
                inactivity_time = (datetime.now() - self.last_activity_time).total_seconds()
                if inactivity_time > self.inactivity_threshold:
                    self.user_active = False
            
            time.sleep(10)
    
    def check_mouse_activity(self):
        class LASTINPUTINFO(ctypes.Structure):
            _fields_ = [("cbSize", ctypes.c_uint),
                        ("dwTime", ctypes.c_uint)]
        
        last_input_info = LASTINPUTINFO()
        last_input_info.cbSize = ctypes.sizeof(last_input_info)
        
        if ctypes.windll.user32.GetLastInputInfo(ctypes.byref(last_input_info)):
            current_tick = ctypes.windll.kernel32.GetTickCount()
            last_input_time = last_input_info.dwTime
            
            # Si activité dans les 10 dernières secondes
            return (current_tick - last_input_time) < 10000
        
        return False
    
    def check_keyboard_activity(self):
        # Vérifier les touches spéciales (peut indiquer une VM)
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Enum") as key:
                subkeys = []
                try:
                    i = 0
                    while True:
                        subkey = winreg.EnumKey(key, i)
                        subkeys.append(subkey)
                        i += 1
                except OSError:
                    pass
                
                # Recherche de périphériques virtuels
                vm_keywords = ["vbox", "vmware", "virtual", "qemu"]
                for subkey in subkeys:
                    if any(kw in subkey.lower() for kw in vm_keywords):
                        return False
        except Exception:
            pass
        
        # Vérifier l'état du clavier
        for key_code in range(0x08, 0xFF):
            state = ctypes.windll.user32.GetAsyncKeyState(key_code)
            # Le bit le moins significatif indique si la touche est enfoncée
            if state & 0x01:
                return True
        
        return False
    
    def check_foreground_process(self):
        hwnd = ctypes.windll.user32.GetForegroundWindow()
        if hwnd:
            pid = ctypes.c_ulong()
            ctypes.windll.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            
            # Obtenir le nom du processus
            process_name = ctypes.create_unicode_buffer(1024)
            h_process = ctypes.windll.kernel32.OpenProcess(0x410, False, pid.value)
            if h_process:
                ctypes.windll.psapi.GetModuleBaseNameW(h_process, None, process_name, 1024)
                ctypes.windll.kernel32.CloseHandle(h_process)
                
                # Processus système communs
                system_processes = ["explorer", "chrome", "firefox", "word", "excel", "notepad"]
                if process_name.value.lower() in system_processes:
                    return True
        
        return False
    
    def is_human_present(self):
        return self.user_active

# Fonction de test
if __name__ == "__main__":
    monitor = UserActivityMonitor()
    monitor.start()
    
    try:
        while True:
            print(f"User active: {monitor.is_human_present()}")
            time.sleep(5)
    except KeyboardInterrupt:
        monitor.stop()