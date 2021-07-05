import tkinter as tk
import threading

from .parser import run

class VulpaGui(tk.Frame):
    def __init__(self, root):
        super().__init__(root)
        self.root = root
        self.pack()
        self.create_gui()

    def yield_activities(self, info):
        self.status_content.set(info)

    def parse_action(self):
        p = threading.Thread(
            target=lambda: run(
                self.before_entry.get(),
                self.after_entry.get(),
                log_function=self.yield_activities))
        p.start()

    def create_gui(self):
        hint_label = tk.Label(self,
            text='Укажите путь к файлам анализов уязвимостей\nв соответствующих полях.\n'
        )
        hint_label.grid(row=1, column=1, columnspan=2, rowspan=2)
        bf_entry_label = tk.Label(self,
            text='XML-файл "До"'
        )
        bf_entry_label.grid(row=3, column=1)
        self.before_entry = tk.Entry(self)
        self.before_entry.grid(row=3, column=2)
        af_entry_label = tk.Label(self,
            text='XML-файл "После"'
        )
        af_entry_label.grid(row=4, column=1)
        self.after_entry = tk.Entry(self)
        self.after_entry.grid(row=4, column=2)

        save_dir_label = tk.Label(self,
            text='Каталог для сохранения отчётов'
        )
        save_dir_label.grid(row=5, column=1)
        self.save_dir_entry = tk.Entry(self)
        self.save_dir_entry.grid(row=5, column=2)
        
        hint_label2 = tk.Label(self,
            text='\n'
        )
        hint_label2.grid(row=6, column=1, columnspan=2)

        run_btn = tk.Button(self,
            text='Запустить',
            command=self.parse_action
        )
        run_btn.grid(row=7, column=1, columnspan=2)

        self.status_content = tk.StringVar()        
        status_label = tk.Label(self,
            textvariable=self.status_content,
            fg='gray',
            wraplength=300
        )
        status_label.grid(row=8, column=1, columnspan=2)
        self.status_content.set('Процесс ещё не начат')

        self.before_entry.insert(0, 'Уязвимости До.xml')
        self.after_entry.insert(0, 'Уязвимости После.xml')
        self.save_dir_entry.insert(0, 'reports')

root = tk.Tk()
root.title('vulpa v0.99')
root.geometry('480x280')
app = VulpaGui(root)
app.mainloop()