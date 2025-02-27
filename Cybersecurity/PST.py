import tkinter as tk
import re

def check_password_strength():
    password = entry.get()
    strength = 0
    
    if len(password) >= 8:
        strength += 1
    if re.search(r'[A-Z]', password):
        strength += 1
    if re.search(r'[a-z]', password):
        strength += 1
    if re.search(r'\d', password):
        strength += 1
    if re.search(r'[@$!%*?&]', password):
        strength += 1
    
    if strength == 5:
        result_label.config(text="Strong Password", fg="green")
        strength_meter.set(100)
        strength_meter.config(bg="green")
    elif strength >= 3:
        result_label.config(text="Medium Password", fg="orange")
        strength_meter.set(60)
        strength_meter.config(bg="orange")
    else:
        result_label.config(text="Weak Password", fg="red")
        strength_meter.set(30)
        strength_meter.config(bg="red")
    
    suggest_improvements(password)

def suggest_improvements(password):
    suggestions = []
    if len(password) < 8:
        suggestions.append("Increase password length to at least 8 characters.")
    if not re.search(r'[A-Z]', password):
        suggestions.append("Add at least one uppercase letter.")
    if not re.search(r'[a-z]', password):
        suggestions.append("Add at least one lowercase letter.")
    if not re.search(r'\d', password):
        suggestions.append("Include at least one number.")
    if not re.search(r'[@$!%*?&]', password):
        suggestions.append("Use at least one special character (@, $, !, %, *, ?, &).")
    
    suggestion_label.config(text="\n".join(suggestions), fg="blue")

# GUI Setup
root = tk.Tk()
root.title("Password Strength Tester")
root.geometry("400x300")

tk.Label(root, text="Enter Password:").pack(pady=5)
entry = tk.Entry(root, show="*", width=30)
entry.pack(pady=5)

check_button = tk.Button(root, text="Check Strength", command=check_password_strength)
check_button.pack(pady=10)

result_label = tk.Label(root, text="", font=("Arial", 12))
result_label.pack()

strength_meter = tk.Scale(root, from_=0, to=100, orient="horizontal", length=200, showvalue=False, bg="gray")
strength_meter.pack(pady=10)

suggestion_label = tk.Label(root, text="", font=("Arial", 10), wraplength=350, justify="left")
suggestion_label.pack()

root.mainloop()
