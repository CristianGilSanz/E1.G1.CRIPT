from login_window import LoginWindow

import tkinter as tk

if __name__ == "__main__":
    logInWnd = tk.Tk()
    app = LoginWindow(logInWnd)
    logInWnd.mainloop()
