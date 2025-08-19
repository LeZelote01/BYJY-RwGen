#!/usr/bin/env python3
"""
Advanced User Activity Monitor
Detects analysis environments through behavioral analysis
For defensive cybersecurity research purposes only
"""

import time
import json
import ctypes
import threading
from ctypes import wintypes
from typing import Dict, List, Tuple, Optional
import win32api
import win32gui
import win32con
import win32process
import psutil
import numpy as np
from datetime import datetime, timedelta


class AdvancedActivityMonitor:
    def __init__(self, monitoring_duration: int = 300):
        self.monitoring_duration = monitoring_duration  # 5 minutes default
        self.activity_data = {
            'mouse_movements': [],
            'key_presses': [],
            'window_changes': [],
            'process_activity': [],
            'network_activity': [],
            'file_operations': []
        }
        self.is_monitoring = False
        self.start_time = None
        
        # Thresholds for human-like behavior
        self.human_thresholds = {
            'min_mouse_movements': 50,
            'min_key_presses': 20,
            'min_window_changes': 5,
            'max_process_creation_rate': 10,  # per minute
            'min_idle_periods': 3,
            'mouse_acceleration_variance': 0.1
        }
    
    def start_monitoring(self) -> Dict:
        """Start comprehensive activity monitoring"""
        print(f"[+] Starting user activity monitoring ({self.monitoring_duration}s)")
        self.is_monitoring = True
        self.start_time = time.time()
        
        # Start monitoring threads
        threads = [
            threading.Thread(target=self._monitor_mouse_activity),
            threading.Thread(target=self._monitor_keyboard_activity),
            threading.Thread(target=self._monitor_window_activity),
            threading.Thread(target=self._monitor_process_activity),
            threading.Thread(target=self._monitor_file_activity)
        ]
        
        for thread in threads:
            thread.daemon = True
            thread.start()
        
        # Wait for monitoring period
        time.sleep(self.monitoring_duration)
        self.is_monitoring = False
        
        # Wait for threads to finish
        for thread in threads:
            if thread.is_alive():
                thread.join(timeout=2)
        
        # Analyze collected data
        return self._analyze_activity_patterns()
    
    def _monitor_mouse_activity(self):
        """Monitor mouse movements and clicks"""
        previous_pos = win32gui.GetCursorPos()
        movement_count = 0
        click_count = 0
        last_movement_time = time.time()
        
        while self.is_monitoring:
            try:
                current_pos = win32gui.GetCursorPos()
                current_time = time.time()
                
                # Detect movement
                if current_pos != previous_pos:
                    movement_delta = (
                        current_pos[0] - previous_pos[0],
                        current_pos[1] - previous_pos[1]
                    )
                    
                    # Calculate movement characteristics
                    distance = np.sqrt(movement_delta[0]**2 + movement_delta[1]**2)
                    time_delta = current_time - last_movement_time
                    
                    self.activity_data['mouse_movements'].append({
                        'timestamp': current_time,
                        'position': current_pos,
                        'delta': movement_delta,
                        'distance': distance,
                        'time_delta': time_delta,
                        'velocity': distance / max(time_delta, 0.001)
                    })
                    
                    previous_pos = current_pos
                    last_movement_time = current_time
                    movement_count += 1
                
                # Detect clicks (simplified detection)
                if win32api.GetKeyState(win32con.VK_LBUTTON) & 0x8000:
                    click_count += 1
                    self.activity_data['mouse_movements'].append({
                        'timestamp': current_time,
                        'event': 'left_click',
                        'position': current_pos
                    })
                
                time.sleep(0.05)  # 20 FPS monitoring
                
            except Exception as e:
                print(f"[!] Mouse monitoring error: {e}")
                break
    
    def _monitor_keyboard_activity(self):
        """Monitor keyboard activity patterns"""
        key_states = {}
        typing_sessions = []
        current_session = []
        
        # Common keys to monitor
        monitored_keys = [
            win32con.VK_SPACE, win32con.VK_RETURN, win32con.VK_BACK,
            win32con.VK_TAB, win32con.VK_SHIFT, win32con.VK_CONTROL
        ]
        
        # Add alphanumeric keys
        for i in range(ord('A'), ord('Z') + 1):
            monitored_keys.append(i)
        for i in range(ord('0'), ord('9') + 1):
            monitored_keys.append(i)
        
        while self.is_monitoring:
            try:
                current_time = time.time()
                keys_pressed = []
                
                for key in monitored_keys:
                    if win32api.GetAsyncKeyState(key) & 0x8001:
                        if key not in key_states or not key_states[key]:
                            # New key press
                            key_states[key] = True
                            keys_pressed.append(key)
                            
                            current_session.append({
                                'timestamp': current_time,
                                'key': key,
                                'key_name': self._get_key_name(key)
                            })
                    else:
                        key_states[key] = False
                
                # Detect typing session boundaries (>2 seconds gap)
                if current_session and current_time - current_session[-1]['timestamp'] > 2.0:
                    if len(current_session) > 3:  # Minimum session length
                        typing_sessions.append(current_session.copy())
                    current_session.clear()
                
                if keys_pressed:
                    self.activity_data['key_presses'].extend(current_session[-len(keys_pressed):])
                
                time.sleep(0.02)  # 50 FPS monitoring
                
            except Exception as e:
                print(f"[!] Keyboard monitoring error: {e}")
                break
        
        # Finalize last session
        if current_session and len(current_session) > 3:
            typing_sessions.append(current_session)
        
        # Analyze typing patterns
        self._analyze_typing_patterns(typing_sessions)
    
    def _get_key_name(self, vk_code: int) -> str:
        """Get readable key name from virtual key code"""
        key_names = {
            win32con.VK_SPACE: 'SPACE',
            win32con.VK_RETURN: 'ENTER',
            win32con.VK_BACK: 'BACKSPACE',
            win32con.VK_TAB: 'TAB',
            win32con.VK_SHIFT: 'SHIFT',
            win32con.VK_CONTROL: 'CTRL'
        }
        
        if vk_code in key_names:
            return key_names[vk_code]
        elif ord('A') <= vk_code <= ord('Z'):
            return chr(vk_code)
        elif ord('0') <= vk_code <= ord('9'):
            return chr(vk_code)
        else:
            return f'VK_{vk_code}'
    
    def _analyze_typing_patterns(self, typing_sessions: List[List[Dict]]):
        """Analyze typing patterns for human-like behavior"""
        if not typing_sessions:
            return
        
        total_keypresses = sum(len(session) for session in typing_sessions)
        
        # Calculate inter-key intervals
        intervals = []
        for session in typing_sessions:
            for i in range(1, len(session)):
                interval = session[i]['timestamp'] - session[i-1]['timestamp']
                intervals.append(interval)
        
        if intervals:
            # Human typing typically has varied intervals (100-300ms average)
            avg_interval = np.mean(intervals)
            interval_variance = np.var(intervals)
            
            self.activity_data['typing_analysis'] = {
                'total_sessions': len(typing_sessions),
                'total_keypresses': total_keypresses,
                'avg_interval': avg_interval,
                'interval_variance': interval_variance,
                'human_like': 0.1 < avg_interval < 0.5 and interval_variance > 0.01
            }
    
    def _monitor_window_activity(self):
        """Monitor window focus changes and interactions"""
        previous_window = None
        window_changes = 0
        
        while self.is_monitoring:
            try:
                current_window = win32gui.GetForegroundWindow()
                
                if current_window != previous_window and current_window != 0:
                    window_title = win32gui.GetWindowText(current_window)
                    
                    try:
                        thread_id, process_id = win32process.GetWindowThreadProcessId(current_window)
                        process_name = psutil.Process(process_id).name()
                    except:
                        process_name = "Unknown"
                    
                    self.activity_data['window_changes'].append({
                        'timestamp': time.time(),
                        'window_handle': current_window,
                        'window_title': window_title,
                        'process_name': process_name
                    })
                    
                    previous_window = current_window
                    window_changes += 1
                
                time.sleep(0.5)  # Check every 500ms
                
            except Exception as e:
                print(f"[!] Window monitoring error: {e}")
                break
    
    def _monitor_process_activity(self):
        """Monitor process creation and termination"""
        known_processes = set(p.pid for p in psutil.process_iter())
        process_events = []
        
        while self.is_monitoring:
            try:
                current_processes = set(p.pid for p in psutil.process_iter())
                
                # New processes
                new_processes = current_processes - known_processes
                for pid in new_processes:
                    try:
                        process = psutil.Process(pid)
                        process_events.append({
                            'timestamp': time.time(),
                            'event': 'created',
                            'pid': pid,
                            'name': process.name(),
                            'cmdline': ' '.join(process.cmdline()),
                            'parent_pid': process.ppid()
                        })
                    except:
                        pass
                
                # Terminated processes
                terminated_processes = known_processes - current_processes
                for pid in terminated_processes:
                    process_events.append({
                        'timestamp': time.time(),
                        'event': 'terminated',
                        'pid': pid
                    })
                
                known_processes = current_processes
                time.sleep(1.0)  # Check every second
                
            except Exception as e:
                print(f"[!] Process monitoring error: {e}")
                break
        
        self.activity_data['process_activity'] = process_events
    
    def _monitor_file_activity(self):
        """Monitor file system activity"""
        try:
            import win32file
            import win32con
            
            # Monitor common directories
            monitored_dirs = [
                "C:\\Users",
                "C:\\Temp",
                "C:\\Windows\\Temp"
            ]
            
            file_events = []
            
            # This is a simplified version - full implementation would use
            # ReadDirectoryChangesW for real-time file monitoring
            initial_files = {}
            for directory in monitored_dirs:
                try:
                    import os
                    if os.path.exists(directory):
                        files = list(os.listdir(directory))
                        initial_files[directory] = set(files)
                except:
                    continue
            
            # Periodic check for changes
            while self.is_monitoring:
                try:
                    for directory in monitored_dirs:
                        if directory not in initial_files:
                            continue
                        
                        try:
                            current_files = set(os.listdir(directory))
                            
                            # New files
                            new_files = current_files - initial_files[directory]
                            for filename in new_files:
                                file_events.append({
                                    'timestamp': time.time(),
                                    'event': 'created',
                                    'directory': directory,
                                    'filename': filename
                                })
                            
                            # Deleted files
                            deleted_files = initial_files[directory] - current_files
                            for filename in deleted_files:
                                file_events.append({
                                    'timestamp': time.time(),
                                    'event': 'deleted',
                                    'directory': directory,
                                    'filename': filename
                                })
                            
                            initial_files[directory] = current_files
                        except:
                            continue
                    
                    time.sleep(5.0)  # Check every 5 seconds
                    
                except Exception as e:
                    print(f"[!] File monitoring error: {e}")
                    break
            
            self.activity_data['file_operations'] = file_events
            
        except ImportError:
            print("[!] File monitoring requires win32file - skipping")
    
    def _analyze_activity_patterns(self) -> Dict:
        """Analyze collected activity data for human-like patterns"""
        analysis_results = {
            'monitoring_duration': self.monitoring_duration,
            'total_mouse_movements': len([m for m in self.activity_data['mouse_movements'] 
                                        if 'position' in m]),
            'total_key_presses': len(self.activity_data['key_presses']),
            'total_window_changes': len(self.activity_data['window_changes']),
            'total_process_events': len(self.activity_data['process_activity']),
            'total_file_operations': len(self.activity_data['file_operations']),
            'human_behavior_score': 0.0,
            'sandbox_indicators': [],
            'analysis_details': {}
        }
        
        score_components = []
        
        # Analyze mouse behavior
        mouse_analysis = self._analyze_mouse_behavior()
        analysis_results['analysis_details']['mouse'] = mouse_analysis
        score_components.append(mouse_analysis.get('human_score', 0))
        
        # Analyze keyboard behavior
        keyboard_analysis = self._analyze_keyboard_behavior()
        analysis_results['analysis_details']['keyboard'] = keyboard_analysis
        score_components.append(keyboard_analysis.get('human_score', 0))
        
        # Analyze window interaction patterns
        window_analysis = self._analyze_window_behavior()
        analysis_results['analysis_details']['windows'] = window_analysis
        score_components.append(window_analysis.get('human_score', 0))
        
        # Analyze process activity
        process_analysis = self._analyze_process_behavior()
        analysis_results['analysis_details']['processes'] = process_analysis
        score_components.append(process_analysis.get('human_score', 0))
        
        # Calculate overall human behavior score
        if score_components:
            analysis_results['human_behavior_score'] = np.mean(score_components)
        
        # Determine if behavior suggests automated/sandbox environment
        analysis_results['likely_automated'] = analysis_results['human_behavior_score'] < 0.3
        analysis_results['likely_human'] = analysis_results['human_behavior_score'] > 0.7
        
        return analysis_results
    
    def _analyze_mouse_behavior(self) -> Dict:
        """Analyze mouse movement patterns"""
        movements = [m for m in self.activity_data['mouse_movements'] if 'velocity' in m]
        
        if len(movements) < 10:
            return {
                'human_score': 0.1,
                'reason': 'Insufficient mouse activity',
                'movement_count': len(movements)
            }
        
        # Analyze movement characteristics
        velocities = [m['velocity'] for m in movements]
        distances = [m['distance'] for m in movements]
        time_deltas = [m['time_delta'] for m in movements]
        
        # Human-like indicators
        velocity_variance = np.var(velocities) if velocities else 0
        avg_distance = np.mean(distances) if distances else 0
        
        # Humans have varied velocity and natural acceleration patterns
        human_score = 0.0
        
        if velocity_variance > 1000:  # Varied movement speeds
            human_score += 0.3
        
        if 5 < avg_distance < 100:  # Reasonable movement distances
            human_score += 0.2
        
        if len(movements) > self.human_thresholds['min_mouse_movements']:
            human_score += 0.3
        
        # Check for too-perfect movements (automation indicator)
        if velocity_variance < 100:  # Too consistent = likely automated
            human_score *= 0.5
        
        return {
            'human_score': min(human_score, 1.0),
            'movement_count': len(movements),
            'velocity_variance': velocity_variance,
            'avg_distance': avg_distance
        }
    
    def _analyze_keyboard_behavior(self) -> Dict:
        """Analyze keyboard input patterns"""
        key_presses = self.activity_data['key_presses']
        
        if len(key_presses) < 10:
            return {
                'human_score': 0.1,
                'reason': 'Insufficient keyboard activity',
                'keypress_count': len(key_presses)
            }
        
        # Analyze typing rhythm
        intervals = []
        for i in range(1, len(key_presses)):
            interval = key_presses[i]['timestamp'] - key_presses[i-1]['timestamp']
            intervals.append(interval)
        
        human_score = 0.0
        
        if intervals:
            avg_interval = np.mean(intervals)
            interval_variance = np.var(intervals)
            
            # Human typing characteristics
            if 0.08 < avg_interval < 0.5:  # 80ms to 500ms between keys
                human_score += 0.4
            
            if interval_variance > 0.01:  # Varied typing rhythm
                human_score += 0.3
            
            if len(key_presses) > self.human_thresholds['min_key_presses']:
                human_score += 0.3
        
        return {
            'human_score': min(human_score, 1.0),
            'keypress_count': len(key_presses),
            'avg_interval': np.mean(intervals) if intervals else 0,
            'interval_variance': np.var(intervals) if intervals else 0
        }
    
    def _analyze_window_behavior(self) -> Dict:
        """Analyze window focus and interaction patterns"""
        window_changes = self.activity_data['window_changes']
        
        if len(window_changes) < 2:
            return {
                'human_score': 0.0,
                'reason': 'No window interactions detected',
                'window_change_count': len(window_changes)
            }
        
        # Analyze window switching patterns
        unique_windows = set(w['process_name'] for w in window_changes)
        
        human_score = 0.0
        
        if len(window_changes) >= self.human_thresholds['min_window_changes']:
            human_score += 0.4
        
        if len(unique_windows) >= 3:  # Multiple different applications
            human_score += 0.3
        
        # Check for realistic application names
        common_apps = ['explorer.exe', 'chrome.exe', 'firefox.exe', 'notepad.exe', 
                      'winword.exe', 'excel.exe', 'outlook.exe']
        if any(app in [w['process_name'].lower() for w in window_changes] for app in common_apps):
            human_score += 0.3
        
        return {
            'human_score': min(human_score, 1.0),
            'window_change_count': len(window_changes),
            'unique_applications': len(unique_windows)
        }
    
    def _analyze_process_behavior(self) -> Dict:
        """Analyze process creation patterns"""
        process_events = self.activity_data['process_activity']
        
        creation_events = [e for e in process_events if e['event'] == 'created']
        
        # Calculate process creation rate
        if self.monitoring_duration > 0:
            creation_rate = len(creation_events) / (self.monitoring_duration / 60.0)  # per minute
        else:
            creation_rate = 0
        
        human_score = 0.0
        
        # Humans typically don't create many processes rapidly
        if creation_rate <= self.human_thresholds['max_process_creation_rate']:
            human_score += 0.5
        
        # Check for suspicious process names
        suspicious_names = ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe']
        suspicious_count = sum(1 for e in creation_events 
                             if any(sus in e.get('name', '').lower() for sus in suspicious_names))
        
        if suspicious_count == 0:
            human_score += 0.3
        elif suspicious_count <= 2:
            human_score += 0.2
        
        return {
            'human_score': min(human_score, 1.0),
            'process_creation_rate': creation_rate,
            'suspicious_processes': suspicious_count,
            'total_process_events': len(process_events)
        }


# Example usage for defensive research
if __name__ == "__main__":
    print("[+] Starting Advanced User Activity Monitor")
    print("[!] This tool is for defensive cybersecurity research only")
    
    # Create monitor instance
    monitor = AdvancedActivityMonitor(monitoring_duration=60)  # 1 minute for demo
    
    # Start monitoring
    results = monitor.start_monitoring()
    
    # Display results
    print("\n" + "="*60)
    print("USER ACTIVITY ANALYSIS RESULTS")
    print("="*60)
    
    print(f"Human Behavior Score: {results['human_behavior_score']:.2f}/1.00")
    print(f"Likely Automated: {'Yes' if results['likely_automated'] else 'No'}")
    print(f"Likely Human: {'Yes' if results['likely_human'] else 'No'}")
    
    print(f"\nActivity Summary:")
    print(f"  Mouse Movements: {results['total_mouse_movements']}")
    print(f"  Key Presses: {results['total_key_presses']}")
    print(f"  Window Changes: {results['total_window_changes']}")
    print(f"  Process Events: {results['total_process_events']}")
    print(f"  File Operations: {results['total_file_operations']}")
    
    # Detailed analysis
    for category, details in results['analysis_details'].items():
        print(f"\n{category.title()} Analysis:")
        for key, value in details.items():
            print(f"  {key}: {value}")
    
    # Save results for research
    with open(f"activity_analysis_{int(time.time())}.json", 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    print("\n[+] Analysis complete - Results saved to JSON file")
    print("[!] Use this data for developing defensive countermeasures")
