import tkinter as tk
from tkinter import ttk, messagebox, font, filedialog
import random
import string
import pyperclip
from cryptography.fernet import Fernet

# Generate encryption key
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Root Window
root = tk.Tk()
root.title("🔑 Password Manager")
root.geometry("900x600")

# Notebook for Tabs
notebook = ttk.Notebook(root)
notebook.pack(fill=tk.BOTH, expand=True)

# Define Tabs
password_tab = ttk.Frame(notebook)
text_editor_tab = ttk.Frame(notebook)
password_storage_tab = ttk.Frame(notebook)

notebook.add(password_tab, text="🔑 Password Generator")
notebook.add(text_editor_tab, text="📝 Secure Notes")
notebook.add(password_storage_tab, text="📂 Saved Passwords")

# Apply Background Function


def apply_background(tab, color1, color2):
    canvas = tk.Canvas(tab, width=900, height=600)
    canvas.pack(fill=tk.BOTH, expand=True)
    for i in range(600):
        r = int((1 - i / 600) *
                int(color1[0:2], 16) + (i / 600) * int(color2[0:2], 16))
        g = int((1 - i / 600) *
                int(color1[2:4], 16) + (i / 600) * int(color2[2:4], 16))
        b = int((1 - i / 600) *
                int(color1[4:6], 16) + (i / 600) * int(color2[4:6], 16))
        canvas.create_line(
            0, i, 900, i, fill=f'#{r:02x}{g:02x}{b:02x}', width=1)
    canvas.lower("all")


apply_background(password_tab, "16222A", "3A6073")
apply_background(text_editor_tab, "23074d", "cc5333")
apply_background(password_storage_tab, "11998e", "38ef7d")

# -------- PASSWORD GENERATOR UI ---------
frame = ttk.Frame(password_tab)
frame.place(relx=0.5, rely=0.5, anchor="center")


def generate_password():
    length = length_var.get()
    chars = (string.ascii_letters if letters_var.get() else "") + \
            (string.digits if numbers_var.get() else "") + \
            (string.punctuation if symbols_var.get() else "")
    if not chars:
        messagebox.showerror("Error", "Select at least one character type.")
        return
    password = ''.join(random.choice(chars) for _ in range(length))
    password_var.set(password)
    tree.insert("", "end", values=(
        cipher_suite.encrypt(password.encode()).decode()))


def copy_password():
    if password_var.get():
        pyperclip.copy(password_var.get())
        messagebox.showinfo("Success", "Password copied!")


length_var = tk.IntVar(value=12)
password_var = tk.StringVar()

ttk.Label(frame, text="Password Length:", font=(
    "Arial", 12, "bold")).grid(row=0, column=0, padx=5, pady=5)
ttk.Entry(frame, textvariable=length_var, width=5, font=(
    "Arial", 12)).grid(row=0, column=1, padx=5, pady=5)

letters_var, numbers_var, symbols_var = tk.BooleanVar(
    value=True), tk.BooleanVar(value=True), tk.BooleanVar(value=True)

ttk.Checkbutton(frame, text="Letters", variable=letters_var).grid(
    row=1, column=1, sticky=tk.W)
ttk.Checkbutton(frame, text="Numbers", variable=numbers_var).grid(
    row=2, column=1, sticky=tk.W)
ttk.Checkbutton(frame, text="Symbols", variable=symbols_var).grid(
    row=3, column=1, sticky=tk.W)

ttk.Button(frame, text="🔄 Generate", command=generate_password).grid(
    row=4, column=0, columnspan=2, pady=10)
ttk.Entry(frame, textvariable=password_var, state="readonly", width=30,
          font=("Arial", 12)).grid(row=5, column=0, padx=5, pady=5)
ttk.Button(frame, text="📋 Copy", command=copy_password).grid(
    row=5, column=1, padx=5, pady=5)

# -------- SECURE NOTES UI (WITH FONT STYLING) ---------


def change_font(*args):
    text_editor.config(font=(font_var.get(), size_var.get()))


def toggle_bold():
    current_font = font.Font(font=text_editor["font"])
    weight = "bold" if current_font.actual(
    )["weight"] == "normal" else "normal"
    new_font = font.Font(family=font_var.get(), size=size_var.get(), weight=weight,
                         slant=current_font.actual()["slant"], underline=current_font.actual()["underline"])
    text_editor.config(font=new_font)


def toggle_italic():
    current_font = font.Font(font=text_editor["font"])
    slant = "italic" if current_font.actual()["slant"] == "roman" else "roman"
    new_font = font.Font(family=font_var.get(), size=size_var.get(), weight=current_font.actual()[
                         "weight"], slant=slant, underline=current_font.actual()["underline"])
    text_editor.config(font=new_font)


def toggle_underline():
    current_font = font.Font(font=text_editor["font"])
    underline = 1 if current_font.actual()["underline"] == 0 else 0
    new_font = font.Font(family=font_var.get(), size=size_var.get(), weight=current_font.actual()[
                         "weight"], slant=current_font.actual()["slant"], underline=underline)
    text_editor.config(font=new_font)


def save_notes():
    file_path = filedialog.asksaveasfilename(
        defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, 'w') as f:
            f.write(text_editor.get("1.0", tk.END))


def open_notes():
    file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, 'r') as f:
            text_editor.delete("1.0", tk.END)
            text_editor.insert(tk.END, f.read())


font_var = tk.StringVar(value="Arial")
size_var = tk.IntVar(value=14)

# Increased font styles and sizes (similar to MS Word)
font_dropdown = ttk.Combobox(text_editor_tab, textvariable=font_var, values=(
    "Arial", "Courier", "Times New Roman", "Verdana", "Georgia", "Comic Sans MS", "Tahoma", "Lucida Console"), state="readonly")
font_dropdown.place(x=20, y=10)
font_dropdown.bind("<<ComboboxSelected>>", change_font)

size_dropdown = ttk.Combobox(text_editor_tab, textvariable=size_var, values=(
    8, 10, 12, 14, 16, 18, 20, 24, 28, 32), state="readonly")
size_dropdown.place(x=160, y=10)
size_dropdown.bind("<<ComboboxSelected>>", change_font)

ttk.Button(text_editor_tab, text="B", command=toggle_bold).place(x=260, y=10)
ttk.Button(text_editor_tab, text="I", command=toggle_italic).place(x=300, y=10)
ttk.Button(text_editor_tab, text="U",
           command=toggle_underline).place(x=340, y=10)

# Save and Open Buttons
ttk.Button(text_editor_tab, text="Save", command=save_notes).place(x=20, y=50)
ttk.Button(text_editor_tab, text="Open", command=open_notes).place(x=100, y=50)

text_editor = tk.Text(text_editor_tab, wrap=tk.WORD,
                      font=("Arial", 14), bg="#252535", fg="white")
text_editor.place(relx=0.5, rely=0.5, anchor="center", width=700, height=400)

# -------- PASSWORD STORAGE UI (ONLY GENERATED PASSWORDS) ---------
tree = ttk.Treeview(password_storage_tab,
                    columns=("Password"), show="headings")
tree.heading("Password", text="🔑 Encrypted Password")
tree.place(relx=0.5, rely=0.4, anchor="center", width=400, height=300)


def delete_password():
    selected_item = tree.selection()
    if selected_item:
        tree.delete(selected_item)


def toggle_password_visibility():
    selected_item = tree.selection()
    if selected_item:
        item = tree.item(selected_item)
        password = item["values"][0]
        decrypted_password = cipher_suite.decrypt(password.encode()).decode()
        if "visible" in item:
            item["values"] = (cipher_suite.encrypt(
                decrypted_password.encode()).decode(),)
            item["tags"] = ()
        else:
            item["values"] = (decrypted_password,)
            item["tags"] = ("visible",)
        tree.item(selected_item, values=item["values"], tags=item["tags"])


ttk.Button(password_storage_tab, text="🗑 Delete Password",
           command=delete_password).place(relx=0.5, rely=0.85, anchor="center")
ttk.Button(password_storage_tab, text="👁️ Toggle Visibility",
           command=toggle_password_visibility).place(relx=0.5, rely=0.92, anchor="center")

root.mainloop()
