import pefile
import sys
import customtkinter
import os
from tkinter import filedialog
from tkinter import messagebox
import pickle
import bz2

# Path setup for resources based on execution context
if getattr(sys, 'frozen', False):
    apidb_file = r"apidb.pickle"
    icon_file = r"iat-tracer.ico"
    application_path = os.path.dirname(sys.executable)
    params_file = os.path.join(application_path, "params.txt")
elif __file__:
    application_path = os.path.dirname(__file__)
    apidb_file = r"assets/apidb.pickle"
    icon_file = r"assets/iat-tracer.ico"
    params_file = "params.txt"

# Flag to handle performance optimizations during mass selection/deselection
perf_flag = 0


class ScrollableCheckBoxFrame(customtkinter.CTkScrollableFrame):
    def __init__(self, master, item_list, command=None, **kwargs):
        super().__init__(master, **kwargs)

        self.command = command
        self.checkbox_list = []
        for item in item_list:
            self.add_item(item)

    def add_item(self, item):
        checkbox = customtkinter.CTkCheckBox(self, text=item)
        if self.command is not None:
            checkbox.configure(command=lambda: self.command(item))
        checkbox.grid(row=len(self.checkbox_list), column=0, pady=(0, 5), sticky="w")
        self.checkbox_list.append(checkbox)

    def get_checked_items(self):
        return [checkbox.cget("text") for checkbox in self.checkbox_list if checkbox.get() == 1]

    def select_all(self):
        global perf_flag
        perf_flag = 1
        for checkbox in self.checkbox_list:
            if not checkbox.get():
                checkbox.select()
        perf_flag = 0

    def deselect_all(self):
        global perf_flag
        perf_flag = 1
        for checkbox in self.checkbox_list:
            if checkbox.get():
                checkbox.deselect()
        perf_flag = 0


class App(customtkinter.CTk):

    def __init__(self):
        super().__init__()
        self.title("IAT-Tracer Configuration")
        self.geometry("800x700")  # Adjusted height to fit the new layout
        self.columnconfigure((0, 1), weight=1)
        self.rowconfigure((0, 1, 2, 3, 4, 5, 6), weight=1)

        # Variables
        self.imports = {}
        self.loaded_functions = {}
        self.clicked_imported_api_functions = set()
        self.clicked_settings_options = set()
        self.settings_options = [
            "CPUID_1_MITIGATION",
            "NUMBEROFPROCESSOR_MITIGATION",
            "GETTICKCOUNT_MITIGATION",
            "MOUSEMOVEMENT_MITIGATION",
            "INSTRUCTION_LEVEL_TRACE",
        ]

        # UI Widgets
        self.choose_button = customtkinter.CTkButton(
            self, text="Choose a File", command=self.choose_button_callback
        )
        self.choose_button.grid(row=0, column=0, padx=10, pady=10, sticky="w")

        # Custom titles
        self.imported_title = customtkinter.CTkLabel(
            self, text="WINAPI to monitor", font=("Arial", 14, "bold")
        )
        self.imported_title.grid(row=1, column=0, padx=10, pady=(10, 0), sticky="n")

        self.settings_title = customtkinter.CTkLabel(
            self, text="Pintool additional settings", font=("Arial", 14, "bold")
        )
        self.settings_title.grid(row=1, column=1, padx=10, pady=(10, 0), sticky="n")

        # Scrollable frames for imports and settings
        self.imported_scrollable_checkbox_frame = ScrollableCheckBoxFrame(
            master=self, item_list=[], command=self.log_imported_choice_user_event, height=300
        )
        self.imported_scrollable_checkbox_frame.grid(row=2, column=0, padx=10, pady=10, sticky="nsew")

        self.settings_scrollable_checkbox_frame = ScrollableCheckBoxFrame(
            master=self,
            item_list=self.settings_options,
            command=self.log_settings_choice_user_event,
            height=300,
        )
        self.settings_scrollable_checkbox_frame.grid(row=2, column=1, padx=10, pady=10, sticky="nsew")

        # Filter boxes below the scrollable frames
        self.imported_search_box = customtkinter.CTkEntry(
            self,
            placeholder_text="Filter Imports",  # Placeholder text
        )
        self.imported_search_box.grid(row=3, column=0, padx=10, pady=10, sticky="ew")
        self.imported_search_box.bind("<KeyRelease>", self.filter_imported_button_callback)

        self.settings_search_box = customtkinter.CTkEntry(
            self,
            placeholder_text="Filter Settings",  # Placeholder text
        )
        self.settings_search_box.grid(row=3, column=1, padx=10, pady=10, sticky="ew")

        # Configurations arranged in a 3x2 grid
        self.config_frame = customtkinter.CTkFrame(self)
        self.config_frame.grid(row=4, column=0, columnspan=2, padx=10, pady=10, sticky="ew")
        self.config_frame.columnconfigure((0, 1, 2), weight=1)

        # Configuration inputs
        self.add_config_item("DELAY_MINIMUM_VALUE (seconds)", "60", 0, 0)
        self.add_config_item("RDTSC_DISTANCE ", "50", 0, 1)
        self.add_config_item("RDTSC_AVG_VALUE ", "20", 1, 0)
        self.add_config_item("Number of Processors :", "8", 1, 1)
        self.add_config_item("HARD_DISK_SIZE (GB)", "200", 2, 0)
        self.add_config_item("RAM_SIZE (GB)", "4", 2, 1)

         # Path selection boxes
        self.add_path_selection("Path to pin.exe", 5, 0, "pin_path")
        self.add_path_selection("Path to honeypot", 5, 1, "honeypot_path")

        # Save button at the bottom, centered
        self.save_button = customtkinter.CTkButton(
            self, text="Save", command=self.save_button_callback
        )
        self.save_button.grid(row=6, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

        # Load API database
        self.load_api_db()

    def add_config_item(self, label_text, default_value, row, col):
        """Helper function to add a configuration item to the config_frame."""
        label = customtkinter.CTkLabel(self.config_frame, text=label_text)
        label.grid(row=row, column=col * 2, padx=5, pady=5, sticky="w")

        entry = customtkinter.CTkEntry(self.config_frame, width=100)
        entry.grid(row=row, column=col * 2 + 1, padx=5, pady=5, sticky="ew")
        entry.insert(0, default_value)
        setattr(self, f"{label_text.split()[0].lower()}_entry", entry)

    def add_path_selection(self, label_text, row, col, attribute_name):
        """Helper function to add a file path selection box."""
        frame = customtkinter.CTkFrame(self)
        frame.grid(row=row, column=col, padx=10, pady=10, sticky="ew")
        frame.columnconfigure(1, weight=1)

        label = customtkinter.CTkLabel(frame, text=label_text)
        label.grid(row=0, column=0, padx=5, pady=5, sticky="w")

        entry = customtkinter.CTkEntry(frame)
        entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        setattr(self, f"{attribute_name}_entry", entry)

        button = customtkinter.CTkButton(
            frame, text="Browse", command=lambda: self.select_file_path(entry)
        )
        button.grid(row=0, column=2, padx=5, pady=5)

    def select_file_path(self, entry):
        """Open a file dialog to select a file and update the entry."""
        filepath = filedialog.askopenfilename(
            initialdir=os.getcwd(), title="Select a File"
        )
        if filepath:
            entry.delete(0, "end")
            entry.insert(0, filepath)

    def resource_path(self, relative_path):
        base_path = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
        return os.path.join(base_path, relative_path)

    def load_api_db(self):
        with bz2.BZ2File(self.resource_path(apidb_file), "rb") as file:
            self.loaded_functions = pickle.load(file)

    def choose_button_callback(self):
        filename = filedialog.askopenfilename(
            initialdir=os.path.dirname(os.path.abspath(__file__)),
            title="Select a File",
            filetypes=(("PE files", ".exe .dll"), ("All files", "*.*")),
        )
        if filename:
            self.load_imports_from_file(filename)

    def load_imports_from_file(self, filename):
        self.imports.clear()
        pe = pefile.PE(filename)
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    dll = entry.dll.decode("utf-8").lower().split(".")[0]
                    name = imp.name.decode("utf-8")
                    self.imports[name] = dll

        self.update_imported_list()

    def update_imported_list(self, filter_text=""):
        filtered_imports = [
            name
            for name in self.imports.keys()
            if filter_text.strip().casefold() in name.casefold()
        ]
        self.imported_scrollable_checkbox_frame.destroy()
        self.imported_scrollable_checkbox_frame = ScrollableCheckBoxFrame(
            master=self,
            item_list=filtered_imports,
            command=self.log_imported_choice_user_event,
            height=300,
        )
        self.imported_scrollable_checkbox_frame.grid(row=2, column=0, padx=10, pady=10, sticky="nsew")

    def update_settings_list(self, filter_text=""):
        filtered_settings = [
            name
            for name in self.settings_options
            if filter_text.strip().casefold() in name.casefold()
        ]
        self.settings_scrollable_checkbox_frame.destroy()
        self.settings_scrollable_checkbox_frame = ScrollableCheckBoxFrame(
            master=self,
            item_list=filtered_settings,
            command=self.log_settings_choice_user_event,
            height=300,
        )
        self.settings_scrollable_checkbox_frame.grid(row=3, column=1, padx=10, pady=10, sticky="nsew")

    def filter_imported_button_callback(self, event=None):
        self.update_imported_list(self.imported_text_filter.get())

    def filter_settings_button_callback(self, event=None):
        self.update_settings_list(self.settings_text_filter.get())

    def log_imported_choice_user_event(self, item):
        if item in self.clicked_imported_api_functions:
            self.clicked_imported_api_functions.remove(item)
        else:
            self.clicked_imported_api_functions.add(item)

    def log_settings_choice_user_event(self, item):
        if item in self.clicked_settings_options:
            self.clicked_settings_options.remove(item)
        else:
            self.clicked_settings_options.add(item)

    def save_button_callback(self):
        # Save the selected API functions to params.txt
        with open(params_file, "w", encoding="utf-8") as file:
            for func in self.clicked_imported_api_functions:
                try:
                    file.write(
                        f"{self.imports[func]};{func};{self.loaded_functions[func]}\n"
                    )
                except KeyError:
                    print(f"Function {func} not found in API DB")

        # Save the settings to config.h
        with open("config.h", "w", encoding="utf-8") as config_file:
            config_file.write("// Auto-generated configuration file\n\n")

            # Save settings checkboxes
            for setting in self.settings_options:
                if setting in self.clicked_settings_options:
                    config_file.write(f"#define {setting} true\n")
                else:
                    config_file.write(f"#define {setting} false\n")

            # Save Delay minimum value (convert seconds to milliseconds)
            delay_value = self.delay_minimum_value_entry.get()
            if delay_value:
                try:
                    delay_ms = int(float(delay_value) * 1000)
                    config_file.write(f"#define DELAY_MINIMUM_VALUE {delay_ms}\n")
                except ValueError:
                    print("Invalid DELAY_MINIMUM_VALUE. Skipping.")

            # Save RDTSC_DISTANCE and RDTSC_AVG_VALUE
            rdtsc_distance = self.rdtsc_distance_entry.get()
            if rdtsc_distance:
                config_file.write(f"#define RDTSC_DISTANCE {rdtsc_distance}\n")

            rdtsc_avg = self.rdtsc_avg_value_entry.get()
            if rdtsc_avg:
                config_file.write(f"#define RDTSC_AVG_VALUE {rdtsc_avg}\n")

            # Save Number of Processors
            processors = self.number_entry.get()
            if processors:
                config_file.write(f"#define NUMBER_OF_PROCESSORS {processors}\n")

            # Save Ram Size
            ram_size = self.ram_size_entry.get()
            if ram_size:
                config_file.write(f"#define RAM_SIZE {ram_size}LL\n")

            # Save Hard Disk Size
            hard_disk_size = self.hard_disk_size_entry.get()
            if hard_disk_size:
                config_file.write(f"#define HARD_DISK_SIZE {hard_disk_size}ULL\n")

            pin_path = self.pin_path_entry.get()
            if pin_path:
                config_file.write(f"#define PIN_PATH \"{pin_path}\"\n")

            honeypot_path = self.honeypot_path_entry.get()
            if honeypot_path:
                config_file.write(f"#define HON_EXE_PATH \"{honeypot_path}\"\n")

        messagebox.showinfo("Save", "Settings saved successfully.")


if __name__ == "__main__":
    # Set appearance mode and theme
    customtkinter.set_appearance_mode("dark")
    customtkinter.set_default_color_theme("blue")

    # Run the application
    app = App()
    app.iconbitmap(app.resource_path(icon_file))
    app.mainloop()
