import datetime
import hashlib
import math
import os
import sys

import capstone
from colorama import Fore, Style
from PyQt5.QtPrintSupport import QPrinter
from reportlab.pdfgen import canvas

import pefile
from PyQt5.QtCore import Qt, QTimer, QRect, QDir, QRectF
from PyQt5.QtGui import QPixmap, QPalette, QBrush, QIcon, QPainter, QColor, QMovie, QFont, QRegion, QImage, \
    QTextDocument, QTextCursor, QTextCharFormat, QPen, QFontMetrics
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel, QPushButton, QStackedWidget, \
    QHBoxLayout, QLineEdit, QFormLayout, QMessageBox, QFrame, QFileDialog, QTextEdit, QPlainTextEdit, QSpacerItem, \
    QSizePolicy, QProgressBar, QScrollArea, QTextBrowser

import sqlite3
import re
import random

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

from Backend2 import Main_For_Backend
from Backend2.SaveFileLocationC import SaveFileLocationC


class CustomTitleBar(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        # layout.setAlignment(Qt.AlignRight)

        self.title_label = QLabel("Malware Detector and Classifier")
        layout.addWidget(self.title_label, alignment=Qt.AlignLeft | Qt.AlignVCenter)

        spacer = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)  # Add an expanding spacer
        layout.addItem(spacer)

        self.minimize_button = QPushButton("")
        self.minimize_button.setIcon(QIcon("minus-circle.svg"))

        self.maximize_button = QPushButton("")
        self.maximize_button.setIcon(QIcon("maximize-2.svg"))

        self.close_button = QPushButton("")
        self.close_button.setIcon(QIcon("x-circle.svg"))

        layout.addWidget(self.minimize_button, alignment=Qt.AlignRight | Qt.AlignVCenter)
        layout.addWidget(self.maximize_button, alignment=Qt.AlignRight | Qt.AlignVCenter)
        layout.addWidget(self.close_button, alignment=Qt.AlignRight | Qt.AlignVCenter)

        self.setLayout(layout)
        self.setStyleSheet("""
                    QWidget {
                        background-color: #2c3e50;
                        color: white;
                        font-size: 14px;
                        padding: 5px;
                    }

                    QLabel {
                        flex: 1;
                    }

                    QPushButton {
                        border: none;
                        background-color: transparent;
                        color: white;
                        padding: 5px;
                    }

                    QPushButton:hover {
                        background-color: #34495e;
                    }
                """)

        self.setFixedHeight(25)

        self.close_button.clicked.connect(self.parent.close)
        self.minimize_button.clicked.connect(self.parent.showMinimized)
        self.maximize_button.clicked.connect(self.toggle_maximize)  # Corrected line

    def toggle_maximize(self):
        if self.parent.isMaximized():
            self.parent.showNormal()
        else:
            self.parent.showMaximized()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        # painter.setBrush(QColor(0, 0, 0, 150))  # Adjust the transparency as needed
        # painter.setBrush(QColor(25, 25, 112, 150))  # Midnight Blue color with transparency
        painter.setBrush(QColor(44, 62, 80, 200))  # Dark Slate Blue color with transparency
        painter.setPen(Qt.NoPen)

        rect = QRect(0, 0, self.width(), self.height())
        region = QRegion(rect)
        painter.drawRoundedRect(rect, 0, 0)
        self.setMask(region)


class ResponsiveLabel(QLabel):
    def resizeEvent(self, event):
        self.setAlignment(Qt.AlignCenter)
        font = self.font()
        font.setPointSize(16)  # Adjust font size as needed
        self.setFont(font)


# styleing class
class StyledLabel(QLabel):
    def __init__(self, text):
        super().__init__(text)
        self.setStyleSheet("""
            QLabel {
                color: white;
                font-size: 12px;
                margin-top: 10px;
                margin-right: 30px;
            }
        """)


class CommandDialogWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("background-color: black;")
        layout = QVBoxLayout(self)

        self.label = QLabel("Command Prompt", self)
        self.label.setStyleSheet("color: white; font-size: 16px;")
        self.label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.label, alignment=Qt.AlignTop)

        self.background_label = QLabel(self)
        self.background_label.setGeometry(0, 0, self.width(), self.height())
        self.background_label.setStyleSheet("background-color: transparent;")

        self.dialog = QPlainTextEdit(self)
        self.dialog.setStyleSheet("color: lime;")  # Set the green text color
        self.dialog.setFont(QFont("Courier New", 10))  # Set the font and size
        self.dialog.setReadOnly(True)

        layout.addWidget(self.background_label)
        layout.addWidget(self.dialog)

        self.timer = QTimer()
        self.timer.timeout.connect(self.scan_malware)
        self.scan_index = 0
        self.messages = [
            "--> Extracting file features for analysis",
            "--> Analyzing file structure",
            "--> Evaluating file size",
            "--> Extracting strings from the file",
            "--> Analyzing file entropy",
            "--> Checking for code obfuscation techniques",
            "--> Identifying specific API calls",
            "--> Analyzing network behavior patterns",
            "--> Extracting file metadata",
            "--> Evaluating file header information",
            "--> Checking for specific file format characteristics",
            "--> Identifying packer or crypter usage",
            "--> Analyzing file's digital signature",
            "--> Extracting behavioral indicators",
            "--> Evaluating code structure and patterns",
            "--> Checking for file encryption methods",
            "--> Identifying anti-analysis mechanisms",
            "--> Analyzing the presence of known malware signatures",
            "--> Extracting file sections and segments",
            "--> Evaluating file imports and exports",
            "--> Checking for the presence of specific file resources",
            "--> Identifying file metadata anomalies",
            "--> Analyzing file's use of dynamic link libraries (DLLs)",
            "--> Extracting features related to code injection",
            "--> Evaluating file's persistence mechanisms",
            "--> Checking for the presence of rootkit-like behavior",
            "--> Identifying packer or protector artifacts",
            "--> Analyzing file's execution flow",
            "--> Extracting behavioral heuristics",
            "--> Evaluating the use of specific APIs and system calls",
            "--> Checking for the presence of known evasion techniques",
            "--> Identifying file's use of encryption algorithms",
            "--> Analyzing the file's string patterns and encoding techniques",
            "--> Extracting features related to file's dropper functionality",
            "--> Evaluating file's command and control communication methods",
            "--> Checking for file's self-replication capabilities",
            "--> Identifying specific exploit techniques used by the file",
            "--> Analyzing file's use of anti-virtual machine techniques",
            "--> Extracting features related to ransomware behavior",
            "--> Evaluating file's sandbox detection and evasion techniques",
            "--> Analyzing file's use of rootkit-like stealth techniques",
            "--> Identifying file's network communication patterns",
            "--> Extracting features related to file's anti-debugging mechanisms",
            "--> Evaluating file's DLL loading behavior",
            "--> Analyzing file's use of process injection techniques",
            "--> Checking for file's code signing anomalies",
            "--> Identifying file's anti-forensic techniques",
            "--> Extracting features related to file's privilege escalation attempts",
            "--> Evaluating file's polymorphic code characteristics",
            "--> Analyzing file's persistence in registry entries",
            "--> Checking for file's anti-sandbox techniques",
            "--> Identifying file's memory manipulation tactics",
            "--> Extracting features related to file's data exfiltration behavior",
            "--> Evaluating file's browser hijacking functionality",
            "--> Analyzing file's packer or crypter entropy",
            "--> Checking for file's rootkit-like file system modifications",
            "--> Identifying file's connection with known malware families",
            "--> Extracting features related to file's command and control infrastructure",
            "--> Evaluating file's system privilege escalation potential",
            "--> Analyzing file's use of anti-analysis virtual machine detection",
            "--> Checking for file's use of anti-reverse engineering techniques",
            "--> Identifying file's behavior pattern deviations",
            "--> Extracting features related to file's anti-emulation mechanisms",
            "--> Evaluating file's code packing entropy",
            "--> Analyzing file's use of shellcode injection techniques",
            "--> Checking for file's polymorphic encryption algorithms",
            "--> Identifying file's stealthiness in memory and process hiding",
            "--> Extracting features related to file's keylogging capabilities",
            "--> Evaluating file's connection with known exploit kits",
            "--> Analyzing file's use of Trojan-like behavior",
            "--> Checking for file's evasion of behavioral analysis techniques",
            "--> Identifying file's connection with known botnets",
            "--> Extracting features related to file's memory scraping behavior",
            "--> Evaluating file's spear-phishing indicators",
            "--> Analyzing file's use of dropper payloads",
            "--> Checking for file's screen capture functionality",
            "--> Identifying file's behavior related to password stealing",
            "--> Extracting features related to file's anti-analysis artifacts",
            "--> Evaluating file's use of code injection techniques",
            "--> Analyzing file's anti-virus evasion methods",
            "--> Checking for file's rootkit-like persistence",
            "--> Identifying file's connection with known ransomware families",
            "--> Extracting features related to file's lateral movement tactics",
            "--> Evaluating file's use of exploit kit integration",
            "--> Analyzing file's use of process hollowing techniques",
            "--> Checking for file's privilege escalation attempts",
            "--> Identifying file's behavior related to backdoor functionality",
            "--> Extracting features related to file's anti-forensic techniques",
            "--> Evaluating file's use of stealth mechanisms",
            "--> Analyzing file's memory scanning behavior",
            "--> Checking for file's connection with known APT groups",
            "--> Identifying file's evasion of sandbox detection methods",
            "--> Extracting features related to file's DNS hijacking capabilities",
            "--> Evaluating file's use of fileless malware attributes",
            "--> Analyzing file's anti-debugging and anti-emulation techniques",
            "--> Checking for file's connection with known cybercrime campaigns",
            "--> Identifying file's behavior related to SSL/TLS interception",
            "--> Extracting features related to file's privilege escalation techniques",
            "--> Evaluating file's use of file-wiping capabilities",
            "--> Analyzing file's traffic hijacking methods"
        ]

    def start_scan(self):
        self.dialog.clear()
        self.scan_index = 0
        self.timer.start(100)

    def scan_malware(self):
        if self.scan_index < 100:
            scan_result = random.choice(self.messages)
            self.dialog.appendPlainText(scan_result)
            self.scan_index += 1
        else:
            self.timer.stop()
            self.dialog.appendPlainText("--> Analyzing.... \n--> Scan complete.")
            # QTimer.singleShot(5000, self.close)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Custom Window")
        self.setWindowIcon(QIcon("logone.png"))
        # self.setGeometry(300, 30, 600, 80)
        self.setGeometry(350, 30, 500, 500)
        self.setWindowFlags(Qt.FramelessWindowHint)

        self.title_bar = CustomTitleBar(self)
        self.setMenuWidget(self.title_bar)

        # self.setWindowIcon(QIcon('logoone.png'))

        self.central_widget = QWidget()
        self.setFixedWidth(700)
        # self.setFixedHeight(600)
        self.setCentralWidget(self.central_widget)

        self.layout = QVBoxLayout(self.central_widget)

        self.stacked_widget = QStackedWidget(self)
        self.layout.addWidget(self.stacked_widget)

        self.progress_bar = None
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_progress)
        self.progress_value = 0

        #
        self.information_text = QLabel(" ")  # Move this line here
        self.information_text.setStyleSheet("color: white;")

        self.file_path = None

        self.information_text = QLabel("")
        self.information_label = QLabel("")

        # Create pages
        self.create_page1()  # Call the function to create page 1
        self.create_page2()  # Call the function to create page 2
        # self.create_page3()  # Call the function to create page 3
        # self.create_page4()  # Call the function to create page 4
        self.create_page5()  # Call the function to create page 5
        self.create_page6()  # Call the function to create page 6

        self.current_page_index = 0
        self.stacked_widget.setCurrentIndex(self.current_page_index)

        self.bottom_buttons_widget = QWidget()
        self.layout.addWidget(self.bottom_buttons_widget, alignment=Qt.AlignBottom)
        self.update_button_visibility()

        # Page 1

    def create_page1(self):
        page1_widget = QWidget(self)
        page1_layout = QVBoxLayout(page1_widget)

        page1_layout.setContentsMargins(30, 80, 30, 50)
        page1_layout.setSpacing(5)

        # Label
        label = QLabel("Cyber Vision")
        label.setAlignment(Qt.AlignCenter)
        label.setStyleSheet("color: red; font-size: 44px; font-family: Palatino Linotype;")
        page1_layout.addWidget(label)

        # Label Description
        label_desc = QLabel("Malware Detection & Classification")
        label_desc.setObjectName(u"label_desc")
        label_desc.setAlignment(Qt.AlignCenter)
        font2 = QFont()
        font2.setPointSize(10)
        label_desc.setFont(font2)
        label_desc.setStyleSheet("color: rgb(211, 211, 211);")
        page1_layout.addWidget(label_desc)

        # Progress Bar

        progress_bar = QProgressBar()
        progress_bar.setRange(0, 100)
        progress_bar.setValue(0)
        progress_bar.setGeometry(100, 630, 521, 25)
        progress_bar.setStyleSheet(u"QProgressBar{\n"
                                   "	\n"
                                   "	background-color: rgb(48, 68, 97);\n"
                                   "	color: rgb(166, 166, 166);\n"
                                   "	border-radius:10px;\n"
                                   "	border-style:none;\n"
                                   "	text-align:center;\n"
                                   "}\n"
                                   "QProgressBar::chunk{\n"
                                   "	\n"
                                   "	border-radius:10px;\n"
                                   "	background-color: qlineargradient(spread:pad, x1:0, y1:0, x2:1, y2:1, stop:0.284091"
                                   "    rgba(46, 54, 100, 255), stop:1 rgba(185, 0, 0, 255));\n "
                                   "\n"
                                   "}"
                                   )
        page1_layout.addWidget(progress_bar)

        self.progress_bar = progress_bar

        # Loading Label
        label_loading = QLabel("Loading....")
        label_loading.setObjectName(u"label_loading")
        label_loading.setAlignment(Qt.AlignCenter)
        label_loading.setStyleSheet("color: rgb(211, 211, 211);")
        page1_layout.addWidget(label_loading)

        # Developed By Label
        label_devep = QLabel("Developed By Nadia Liaquat")
        label_devep.setObjectName(u"label_devep")
        label_devep.setAlignment(Qt.AlignRight)
        label_devep.setFont(font2)
        label_devep.setStyleSheet("color: rgb(211, 211, 211);")
        page1_layout.addWidget(label_devep)

        # self.stacked_widget.addWidget(QWidget(self))
        self.stacked_widget.addWidget(page1_widget)
        self.current_page_index = 0

        self.timer.start(100)

    def update_progress(self):
        self.progress_value += 1
        if self.progress_bar is not None:
            if self.progress_value <= 100:
                self.progress_bar.setValue(self.progress_value)
            else:
                self.timer.stop()  # Stop the timer
                self.show_next_page()  # Transition to the next page
        # Page 2

    def create_page2(self):
        page2_widget = QWidget(self)
        page2_layout = QVBoxLayout(page2_widget)
        page2_layout.setContentsMargins(0, 70, 0, 30)  # Remove margins
        page2_layout.setSpacing(0)  # Remove spacing

        logo_label = ResponsiveLabel()
        # logo_pixmap = QPixmap("lgu.png")  # Replace with your logo image path
        logo_pixmap = QPixmap("lgu1.png").scaledToWidth(self.width() // 4)
        # logo_pixmap = logo_pixmap.scaledToWidth(150)  # Adjust width as needed
        logo_label.setPixmap(logo_pixmap)
        page2_layout.addWidget(logo_label)

        heading_label = QLabel("Lahore Garrison University")
        heading_font_size = self.width() // 40  # Adjust the value for font size
        heading_label.setStyleSheet(f"font-size: {heading_font_size}px; color: white; font-weight: bold;")
        heading_label.setAlignment(Qt.AlignCenter)
        page2_layout.addWidget(heading_label)

        paragraph_label = QLabel(
            "I am Nadia Liaquat, a final year student in the Department \n"
            "of Cyber Security at Lahore Garrison University.For my pr- \n"
            "oject, I am developing a malware detection and classifier  \n"
            "software that aims to enhance the security of computer sy- \n"
            "stems. I would like to express my sincere gratitude to my  \n"
            "supervisor for the invaluable guidance and support throug- \n"
            "hout this project. Thank you for helping me achieve my ac- \n"
            "ademic goals.")

        font_size = self.width() // 50  # Adjust the value to control font size relative to window width
        paragraph_label.setStyleSheet(f"font-size: {font_size}px; color: white;")
        paragraph_label.setAlignment(Qt.AlignJustify)  # Set text alignment to justify
        page2_layout.addWidget(paragraph_label)

        paragraph_label.setAlignment(Qt.AlignCenter)
        page2_layout.addWidget(paragraph_label)

        self.stacked_widget.addWidget(page2_widget)

        # Page 3

    def create_page5(self):
        page5_widget = QWidget(self)
        page5_layout = QVBoxLayout(page5_widget)

        logo_layout = QHBoxLayout()

        logo_label_page5 = ResponsiveLabel()
        # logo_pixmap_page5 = QPixmap("logoone.png")  # Replace with your logo image path
        # logo_pixmap_page5 = logo_pixmap_page5.scaledToWidth(self.width() // 4)
        # logo_label_page5.setPixmap(logo_pixmap_page5)
        logo_layout.addWidget(logo_label_page5)
        # page5_layout.addWidget(logo_label_page5)

        browse_button = QPushButton("Browse File")
        browse_button.clicked.connect(self.browse_file)
        logo_layout.addWidget(browse_button)

        page5_layout.addLayout(logo_layout)
        #
        info_and_command_layout = QHBoxLayout()
        #
        #
        #
        # # Create a scroll area for the information frame
        #
        # information_scroll_area = QScrollArea()
        # information_scroll_area.setWidgetResizable(True)
        # information_frame = QFrame(information_scroll_area)
        # information_frame.setStyleSheet("background-color: black;")
        # information_frame.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        # information_scroll_area.setWidget(information_frame)
        #
        # information_layout = QVBoxLayout(information_frame)
        #
        #
        # self.information_text = QLabel("")
        # self.information_text.setStyleSheet("color: white;")
        # information_layout.addWidget(self.information_text)
        #
        # # Add the information_scroll_area to the layout
        # info_and_command_layout.addWidget(information_scroll_area)

        # Create a scroll area for the command dialog frame
        command_dialog_scroll_area = QScrollArea()
        command_dialog_scroll_area.setWidgetResizable(True)
        command_dialog_scroll_area.setStyleSheet("background-color: black;")
        command_dialog_frame = QFrame(command_dialog_scroll_area)
        command_dialog_frame.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        command_dialog_scroll_area.setWidget(command_dialog_frame)

        command_dialog_layout = QVBoxLayout(command_dialog_frame)

        self.command_dialog = CommandDialogWidget()
        if self.file_path:
            self.command_dialog.start_scan()

        command_dialog_layout.addWidget(self.command_dialog)

        # # Add the command_dialog_scroll_area to the layout
        # info_and_command_layout.addWidget(command_dialog_scroll_area)
        #
        # # Add the horizontal layout to the page5_layout
        # page5_layout.addLayout(info_and_command_layout)
        #
        # self.stacked_widget.addWidget(page5_widget)

        # Add the command_dialog_scroll_area to the layout
        info_and_command_layout.addWidget(command_dialog_scroll_area)

        # Create a scroll area for the information frame
        information_scroll_area = QScrollArea()
        information_scroll_area.setWidgetResizable(True)
        information_scroll_area.setStyleSheet("background-color: black;")
        information_frame = QFrame(information_scroll_area)
        information_frame.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        information_scroll_area.setWidget(information_frame)

        information_layout = QVBoxLayout(information_frame)
        # information_layout.setSpacing(2)

        # Add a label for the information block
        information_block_label = QLabel("Information")
        information_block_label.setStyleSheet("color: white; font-size: 20px;")
        # information_block_label.addwidget(alignment=Qt.AlignTop | Qt.AlignHCenter)
        # information_block_label.setAlignment(Qt.AlignCenter)
        information_block_label.setContentsMargins(3, 0, 0, 3)
        information_layout.addWidget(information_block_label, alignment=Qt.AlignTop | Qt.AlignHCenter)

        self.information_text = QLabel("")
        self.information_text.setStyleSheet("color: white;")
        information_layout.addWidget(self.information_text, alignment=Qt.AlignTop)

        # Add the information_scroll_area to the layout
        info_and_command_layout.addWidget(information_scroll_area)

        # Add the horizontal layout to the page5_layout
        page5_layout.addLayout(info_and_command_layout)

        self.stacked_widget.addWidget(page5_widget)

    # Page 6

    def create_page6(self):
        page6_widget = QWidget(self)
        page6_layout = QVBoxLayout(page6_widget)

        logo_layout_page6 = QHBoxLayout()

        logo_label_page6 = ResponsiveLabel()
        # logo_pixmap_page6 = QPixmap("logoone.png")  # Replace with your logo image path
        # logo_pixmap_page6 = logo_pixmap_page6.scaledToWidth(self.width() // 4)
        # logo_label_page6.setPixmap(logo_pixmap_page6)
        logo_layout_page6.addWidget(logo_label_page6)

        page6_layout.addLayout(logo_layout_page6)

        menu_and_info_layout = QHBoxLayout()

        # Frame for Menu Bar with Buttons
        menu_frame = QFrame()
        menu_frame.setFixedWidth(self.width() // 4)
        menu_frame.setFixedHeight(400)
        menu_frame.setStyleSheet("background-color: rgba(0, 0, 0, 0.5);")
        menu_layout = QVBoxLayout(menu_frame)

        button1 = QPushButton("Details")
        button1.setStyleSheet("color: white;")
        button2 = QPushButton("Dlls")
        button2.setStyleSheet("color: white;")
        button3 = QPushButton("APIs")
        button3.setStyleSheet("color: white;")
        button4 = QPushButton("Strings")
        button4.setStyleSheet("color: white;")
        button5 = QPushButton("Disassembly")
        button5.setStyleSheet("color: white;")
        report_button = QPushButton("Generate Report")
        report_button.setStyleSheet("color: white;")

        # Add more buttons as needed

        menu_layout.addWidget(button1)
        menu_layout.addWidget(button2)
        menu_layout.addWidget(button3)
        menu_layout.addWidget(button4)
        menu_layout.addWidget(button5)
        menu_layout.addWidget(report_button)
        # Add more buttons to the layout

        menu_and_info_layout.addWidget(menu_frame)

        information_scroll_area = QScrollArea()
        information_scroll_area.setWidgetResizable(True)
        information_frame = QFrame(information_scroll_area)
        information_frame.setStyleSheet("background-color: black;")
        information_frame.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        information_scroll_area.setWidget(information_frame)

        information_layout = QVBoxLayout(information_frame)

        self.information_label = QLabel("Initial Information Display")  # Define information_label as a class attribute
        self.information_label.setStyleSheet("color: white;")
        information_layout.addWidget(self.information_label)

        # Connect button clicks to display information
        button1.clicked.connect(self.show_details_information)
        button2.clicked.connect(self.show_dlls_information)
        button3.clicked.connect(self.show_apis_information)
        button4.clicked.connect(self.show_strings_information)
        button5.clicked.connect(self.show_disassembly_information)
        report_button.clicked.connect(self.generate_report)

        # Add the information_scroll_area to the layout
        menu_and_info_layout.addWidget(information_scroll_area)

        # Set up the main layout
        page6_layout.addLayout(menu_and_info_layout)
        page6_widget.setLayout(page6_layout)
        self.stacked_widget.addWidget(page6_widget)

    def show_page5(self):
        self.create_page5()  # Call the method to create and set up page5
        self.stacked_widget.setCurrentIndex(4)

    def browse_file(self):
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        file_path, _ = QFileDialog.getOpenFileName(self, "Open File", "", "All Files (*);;Text Files (*.txt)",
                                                   options=options)

        # callingBckEnd()
        saveFileLocationC = SaveFileLocationC()
        saveFileLocationC.setFileLocation(file_path)

        if file_path:
            self.file_path = file_path
            self.selected_file_path = file_path

            # self.call_command_dialog()
            self.command_dialog.start_scan()  # Call start_scan when file is selected

            isMalware = Main_For_Backend.analysising_Given_file()

            print(f"Is Malware {isMalware}")
            # ===================================================================================
            # ========================================File size,File Location========================================
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            file_type = os.path.splitext(file_name)[1]

            # Convert file size to a human-readable format
            size_suffixes = ['B', 'KB', 'MB', 'GB', 'TB']
            index = 0
            while file_size > 1024 and index < len(size_suffixes) - 1:
                file_size /= 1024
                index += 1
            file_size = f"{file_size:.2f} {size_suffixes[index]}"

            # ===================================================================================
            # =====================================Processing============================================
            try:
                if isMalware == "Not Malware":
                    global info_textS
                    info_textS = f"<b>File Name : </b> {file_name}<br><b>File Size : </b> {file_size}<br><b>File Type : </b> {file_type}<br><b>File Path : </b> {file_path}<br><b>File Status : </b>As a AI Model I Am Sure This File Is Not A Malware File.This Is Benign File <br>"
                    self.information_text.setText(info_textS)
                if isMalware == False:
                    info_textS = f"<b>File Name : </b> {file_name}<br><b>File Size : </b> {file_size}<br><b>File Type : </b> {file_type}<br><b>File Path : </b> {file_path}<br><b>File Status : </b>As a AI Model Currently I Am Unable To Detect This Type File  <br>"
                    self.information_text.setText(info_textS)
                if isinstance(isMalware, dict):
                    if isMalware.get('FileStatus_From_CNN') != isMalware.get('FileStatus_From_ResNet'):
                        info_textS = f"<b>File Name : </b> {file_name}<br><b>File Size : </b> {file_size}<br><b>File Type : </b> {file_type}<br><b>File Path : </b> {file_path}<br><b>File Status : </b>I am Not Sure about this file But this type of files seem like were used for Malicious Activity in Past <br>"
                        self.information_text.setText(info_textS)
                    else:
                        info_textS = f"<b>File Name : </b> {file_name}<br><b>File Size : </b> {file_size}<br><b>File Type : </b> {file_type}<br><b>File Path : </b> {file_path}<br><b>CNN model:</b> <b>{isMalware.get('Confidence_From_CNN')}% Sure</b> <b> This File Is </b><b>{isMalware.get('FileStatus_From_CNN')}</b><b> \n Other ResNet Model {isMalware.get('Confidence_From_ResNet')}% Sure This File Is {isMalware.get('FileStatus_From_ResNet')} </b> <br>"
                        self.information_text.setText(info_textS)

                        if isMalware.get('FileStatus_From_CNN') == "Malware" and isMalware.get(
                                'FileStatus_From_ResNet') == "Malware":
                            malwareFamily = Main_For_Backend.showMalwareFamilies()
                            if malwareFamily == False:
                                # I Am Unable To Detect This Malware Family
                                info_textS = f"<b>File Name : </b> {file_name}<br><b>File Size : </b> {file_size}<br><b>File Type : </b> {file_type}<br><b>File Path : </b> {file_path}<br><b>CNN Model : </b> <b>{isMalware.get('Confidence_From_CNN')}% Sure</b> <b> This File Is </b><b>{isMalware.get('FileStatus_From_CNN')}</b><b> Other ResNet Model {isMalware.get('Confidence_From_ResNet')}% Sure This File Is {isMalware.get('FileStatus_From_ResNet')} </b> <br><b>Currently I Am Unable To Detect This Malware Family</b>"
                                self.information_text.setText(info_textS)



                            else:
                                info_textS = f"<b>File Name : </b> {file_name}<br><b>File Size : </b> {file_size}<br><b>File Type : </b> {file_type}<br><b>File Path : </b> {file_path}<br><b>CNN Model : </b> <b>{isMalware.get('Confidence_From_CNN')}% Sure</b> <b> This File Is</b><b>{isMalware.get('FileStatus_From_CNN')}</b><b> ResNet Model {isMalware.get('Confidence_From_ResNet')}% Sure This File Is {isMalware.get('FileStatus_From_ResNet')} </b> <br><b>In Past This Type Malware Use as {malwareFamily}</b>"
                                self.information_text.setText(info_textS)

            except Exception as e:
                print(f"Here is Error is {str(e)}")
        # ===================================================================================

        # self.information_text.setText(f"Selected File: {self.selected_file_path}")  # Update the text

    def call_command_dialog(self):
        self.command_dialog = CommandDialogWidget()
        self.command_dialog.start_scan()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.fillRect(event.rect(), QBrush(QColor(255, 255, 255)))  # Fill with white background color
        pixmap = QPixmap('background.jpg')  # Replace with your background image path
        pixmap = pixmap.scaled(self.size(), Qt.IgnoreAspectRatio, Qt.SmoothTransformation)
        painter.drawPixmap(0, 0, pixmap)

    def draw_background_image(self, painter, printer):
        # Load your background image
        bg_image = QImage("background.jpg")

        # Ensure the image covers the entire page
        bg_image = bg_image.scaled(printer.pageRect().size(), Qt.IgnoreAspectRatio, Qt.SmoothTransformation)

        # Draw the background image
        painter.drawImage(printer.pageRect(), bg_image)

    def create_bottom_buttons(self, show_back=True, show_exit=True, show_next=False):
        bottom_buttons_layout = QHBoxLayout()

        if show_back:
            back_button = QPushButton("Back")
            back_button.clicked.connect(self.show_previous_page)
            back_button.setCursor(Qt.PointingHandCursor)
            back_button.setStyleSheet("""
                        QPushButton {
                            background-color: #2c3e50;
                            color: white;
                            padding: 5px;
                            border: 2px solid '#800020';
                            border-radius: 8px;
                            margin-right: 50px;
                            margin-left: 50px;
                        }
                        QPushButton:hover {
                            background-color: #800020;
                        }
                    """)
            bottom_buttons_layout.addWidget(back_button)

        if show_exit:
            exit_button = QPushButton("Exit")
            exit_button.clicked.connect(self.close)
            exit_button.setCursor(Qt.PointingHandCursor)
            exit_button.setStyleSheet("""
                QPushButton {
                    background-color: #2c3e50;
                    color: white;
                    padding: 5px;
                    border: 2px solid '#800020';
                    border-radius: 8px;
                    margin-right: 50px;
                    margin-left: 50px;
                }
                QPushButton:hover {
                    background-color: #800020;
                }
            """)
            bottom_buttons_layout.addWidget(exit_button)

        if show_next:
            next_button = QPushButton("Next")
            next_button.clicked.connect(self.show_next_page)
            next_button.setCursor(Qt.PointingHandCursor)
            next_button.setStyleSheet("""
                        QPushButton {
                            background-color: #2c3e50;
                            color: white;
                            padding: 5px;
                            border: 2px solid '#800020';
                            border-radius: 8px;
                            margin-right: 50px;
                            margin-left: 50px;
                        }
                        QPushButton:hover {
                            background-color: #800020;
                        }
                    """)
            bottom_buttons_layout.addWidget(next_button)

        self.bottom_buttons_widget = QWidget()
        self.bottom_buttons_widget.setLayout(bottom_buttons_layout)
        self.layout.addWidget(self.bottom_buttons_widget, alignment=Qt.AlignBottom)

    def update_button_visibility(self):
        # Hide all buttons
        self.bottom_buttons_widget.hide()

        # Get current page index
        current_page_index = self.stacked_widget.currentIndex()

        # Get the requested button visibility for the current page
        show_back, show_exit, show_next = self.get_button_visibility(current_page_index)

        # Update the button widget's layout based on the requested visibility
        self.create_bottom_buttons(show_back, show_exit, show_next)

        # Show the button widget
        self.bottom_buttons_widget.show()

    def get_button_visibility(self, page_index):
        # Determine button visibility based on the page index
        if page_index == 0:
            return False, False, False
        elif page_index == 1:
            return True, True, True
        elif page_index == 2:
            return True, True, True
        elif page_index == 3:
            return True, True, True
        elif page_index == 4:
            return True, True, True
        elif page_index == 5:
            return True, True, True

    def show_previous_page(self):
        if self.current_page_index > 0:
            self.current_page_index -= 1
            self.stacked_widget.setCurrentIndex(self.current_page_index)
            self.update_button_visibility()  # Update button visibility after changing page

    def show_next_page(self):
        if self.current_page_index < self.stacked_widget.count() - 1:
            self.current_page_index += 1
            self.stacked_widget.setCurrentIndex(self.current_page_index)
            self.update_button_visibility()  # Update button visibility after changing page

    # File Analysis
    def show_details_information(self):
        # Call the function to calculate file properties
        # file_path = 'ming.exe'  # Replace with the actual file path
        if self.file_path:
            file_properties = self.calculate_file_properties(self.file_path)

            # Create a formatted string to display file properties
            info_text = f"MD5 : {file_properties['MD5']}\n"
            info_text += f"SHA-1 : {file_properties['SHA-1']}\n"
            info_text += f"SHA-256 : {file_properties['SHA-256']}\n"
            info_text += f"ImpHash : {file_properties['ImpHash']}\n"
            info_text += f"File Size : {file_properties['File Size']}\n"
            info_text += f"Entry Point : {file_properties['Entry Point']}\n"
            info_text += f"Entropy : {file_properties['Entropy']}\n"
            info_text += f"CPU : {file_properties['CPU']}\n"
            info_text += f"Compiler Stamp : {file_properties['Compiler Stamp']}\n"
            info_text += f"Major Operating System Version : {file_properties['MajorOperatingSystemVersion']}\n"
            info_text += f"Signature : {file_properties['Signature']}\n"
            info_text += f"File Path : {file_properties['File Path']}"

            # Set the information label text to display the calculated properties
            self.information_label.setText(info_text)
        else:
            self.information_label.setText("No file selected.")

        return info_text

    def set_information_label(self, text):
        self.information_label.setText(text)

    def calculate_file_properties(self, file_path):
        results = {}

        # Adding the file path
        results['File Path'] = os.path.abspath(file_path)

        # Calculate MD5, SHA-1, and SHA-256 hashes
        with open(file_path, 'rb') as f:
            data = f.read()
            md5_hash = hashlib.md5(data).hexdigest()
            sha1_hash = hashlib.sha1(data).hexdigest()
            sha256_hash = hashlib.sha256(data).hexdigest()
            results['MD5'] = md5_hash
            results['SHA-1'] = sha1_hash
            results['SHA-256'] = sha256_hash

        # Calculate imphash
        pe = pefile.PE(file_path)
        imphash = pe.get_imphash()
        results['ImpHash'] = imphash

        # File size
        file_size = os.path.getsize(file_path)
        results['File Size'] = self.convert_bytes_to_human_readable(file_size)

        # Entry point
        entry_point = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        results['Entry Point'] = entry_point

        # Entropy
        entropy = self.calculate_entropy(data)
        results['Entropy'] = entropy

        # CPU, Compiler Stamp, Debugger Stamp, Signature (if available)
        cpu_name = self.get_cpu_name(pe.FILE_HEADER.Machine)
        results['CPU'] = cpu_name
        compiler_stamp = pe.FILE_HEADER.TimeDateStamp
        compiler_date = datetime.datetime.fromtimestamp(compiler_stamp)
        results['Compiler Stamp'] = compiler_date

        results['MajorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
        results['Signature'] = pe.OPTIONAL_HEADER.CheckSum

        return results

    def convert_bytes_to_human_readable(self, size_in_bytes):
        if size_in_bytes < 1024:
            return f"{size_in_bytes} B"
        elif size_in_bytes < 1024 ** 2:
            return f"{size_in_bytes / 1024:.2f} KB"
        elif size_in_bytes < 1024 ** 3:
            return f"{size_in_bytes / (1024 ** 2):.2f} MB"
        else:
            return f"{size_in_bytes / (1024 ** 3):.2f} GB"

    def get_cpu_name(self, machine_code):
        cpu_names = {
            0x0: "IMAGE_FILE_MACHINE_UNKNOWN",
            0x1d3: "IMAGE_FILE_MACHINE_AM33",
            0x14c: "IMAGE_FILE_MACHINE_I386",
            0x186: "IMAGE_FILE_MACHINE_IA64",
            0x200: "IMAGE_FILE_MACHINE_M32R",
            0x268: "IMAGE_FILE_MACHINE_MIPS16",
            0x366: "IMAGE_FILE_MACHINE_MIPSFPU",
            0x466: "IMAGE_FILE_MACHINE_MIPSFPU16",
            0x1f0: "IMAGE_FILE_MACHINE_POWERPC",
            0x1f1: "IMAGE_FILE_MACHINE_POWERPCFP",
            0x166: "IMAGE_FILE_MACHINE_R4000",
            0x5032: "IMAGE_FILE_MACHINE_RISCV32",
            0x5064: "IMAGE_FILE_MACHINE_RISCV64",
            0x5128: "IMAGE_FILE_MACHINE_RISCV128",
            0x1c4: "IMAGE_FILE_MACHINE_ARMNT",
            0xaa64: "IMAGE_FILE_MACHINE_ARM64",
            0x1c0: "IMAGE_FILE_MACHINE_ARM64EC",
            0x284: "IMAGE_FILE_MACHINE_ARMV7",
            0x285: "IMAGE_FILE_MACHINE_ARMV7S",
            0xebc: "IMAGE_FILE_MACHINE_EBC",
            0x9041: "IMAGE_FILE_MACHINE_HITACHI_SH3",
            0x7045: "IMAGE_FILE_MACHINE_HITACHI_SH3DSP",
            0x9120: "IMAGE_FILE_MACHINE_HITACHI_SH4",
            # Add more CPU architecture codes and names here
        }
        return cpu_names.get(machine_code, "Unknown CPU")

    def calculate_entropy(self, data):
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        return entropy

    def extract_apis_from_exe(self, exe_file_path):
        api_dict = {}

        try:
            pe = pefile.PE(exe_file_path)
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8")
                api_list = []
                for import_data in entry.imports:
                    if import_data.name:
                        api_list.append(import_data.name.decode("utf-8"))
                api_dict[dll_name] = api_list
        except Exception as e:
            print(f"Error extracting APIs: {e}")

        return api_dict

    def show_apis_information(self):
        # file_name = 'ming.exe'  # Replace with the actual file name
        if self.file_path:
            apis = self.extract_apis_from_exe(self.file_path)

            info_text = ""
            for dll, api_list in apis.items():
                info_text += f"------------  APIs imported from {dll} :  ------------ \n"
                for api in api_list:
                    info_text += f"{api}\n"

            self.information_label.setText(info_text)
        else:
            self.information_label.setText("No file selected.")

        return info_text

    def extract_dlls_from_exe(self, exe_file_path):
        dll_list = []

        try:
            pe = pefile.PE(exe_file_path)
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                if entry.dll:
                    dll_name = entry.dll.decode("utf-8")
                    if dll_name not in dll_list:
                        dll_list.append(dll_name)
        except Exception as e:
            print(f"Error extracting DLLs: {e}")

        return dll_list

    def show_dlls_information(self):
        # file_name = 'ming.exe'  # Replace with the actual file name
        if self.file_path:
            dlls = self.extract_dlls_from_exe(self.file_path)

            info_text = "------------  DLLs imported by the File:  ------------ \n"
            for dll in dlls:
                info_text += f"{dll}\n"

            self.information_label.setText(info_text)
        else:
            self.information_label.setText("No file selected.")

        return info_text

    def is_human_readable_ascii(self, s, min_length=10):
        return all(32 <= ord(c) <= 126 for c in s) and len(s) >= min_length

    def extract_strings_from_exe(self, exe_file_path, min_length=10):
        strings_list = []

        try:
            pe = pefile.PE(exe_file_path)
            for section in pe.sections:
                section_data = section.get_data()
                ascii_string = ""
                for byte in section_data:
                    if 32 <= byte <= 126:  # Printable ASCII range
                        ascii_string += chr(byte)
                    else:
                        if self.is_human_readable_ascii(ascii_string, min_length):
                            strings_list.append(ascii_string)
                        ascii_string = ""
                if self.is_human_readable_ascii(ascii_string, min_length):
                    strings_list.append(ascii_string)
        except Exception as e:
            print(f"Error extracting strings: {e}")

        return strings_list

    def show_strings_information(self):
        # file_name = 'ming.exe'  # Replace with the actual file name
        if self.file_path:
            strings = self.extract_strings_from_exe(self.file_path)

            info_text = "------------ ALL STRINGS:  ------------\n"
            for st in strings[:500]:
                info_text += f"{st}\n"

            self.information_label.setText(info_text)

        else:
            self.information_label.setText("No file selected.")

        return info_text

    def determine_architecture(self, file_path):
        pe = pefile.PE(file_path)
        if pe.FILE_HEADER.Machine == 0x14C:  # IMAGE_FILE_MACHINE_I386
            return capstone.CS_ARCH_X86, capstone.CS_MODE_32
        elif pe.FILE_HEADER.Machine == 0x8664:  # IMAGE_FILE_MACHINE_AMD64
            return capstone.CS_ARCH_X86, capstone.CS_MODE_64
        else:
            raise ValueError("Unsupported architecture")

    # Disassemble a given instruction
    def disassemble(self, md, instruction, offset):
        return md.disasm(instruction, offset)

    def disassemble_file(self, file_path):
        arch, mode = self.determine_architecture(file_path)
        md = capstone.Cs(arch, mode)

        with open(file_path, "rb") as f:
            binary = f.read()

        # Find the start of the code section
        code_start = 0
        for i in range(len(binary)):
            if binary[i] == b"\x48"[0]:
                # This is the start of a 64-bit instruction
                code_start = i
                break

        # Disassemble the code section
        instructions = []
        for i in range(code_start, len(binary), 4):
            instruction = binary[i:i + 4]
            disassembled_instructions = self.disassemble(md, instruction, code_start + i)
            for disassembled_instruction in disassembled_instructions:
                instructions.append(disassembled_instruction)

        return instructions

    def show_disassembly_information(self):
        # file_name = 'ming.exe'  # Replace with the actual file name
        # instructions = disassemble_file("ming.exe")
        # # Print the disassembled instructions
        # for instruction in instructions:
        #     print(f"{instruction.address:08x}\t{instruction.mnemonic}\t{instruction.op_str}")

        if self.file_path:
            instructions = self.disassemble_file(self.file_path)

            info_text = "------------ Disassembly :  ------------\n"
            for instruction in instructions:
                info_text += f"{instruction.address:08x}\t{instruction.mnemonic}\t{instruction.op_str}\n"

            self.information_label.setText(info_text)

        else:
            self.information_label.setText("No file selected.")

        return info_text

    def save_disassembly_to_file(self, disassembly_text, file_path):
        try:
            with open(file_path, 'w') as file:
                file.write(disassembly_text)
        except Exception as e:
            print(f"Error saving disassembly to file: {e}")

    def generate_report(self):
        try:
            file_path, _ = QFileDialog.getSaveFileName(self, "Save Report", "", "PDF Files (*.pdf);;All Files (*)")
            if file_path:

                information_text = self.information_text.text()
                details_text = self.show_details_information()
                dlls_text = self.show_dlls_information()
                apis_text = self.show_apis_information()
                strings_text = self.show_strings_information()
                disassemble_text = self.show_disassembly_information()

                html_to_text = QTextDocument()
                html_to_text.setHtml(information_text)
                information_text = html_to_text.toPlainText()

                printer = QPrinter()
                printer.setOutputFormat(QPrinter.PdfFormat)
                printer.setOutputFileName(file_path)

                painter = QPainter()
                painter.begin(printer)

                # Save disassembly code to a separate file
                disassembly_file_path = "disassembly_code.txt"
                self.save_disassembly_to_file(disassemble_text, disassembly_file_path)

                # Define margins
                top_margin = 72  # 1 inch from the top
                bottom_margin = 72  # 1 inch from the bottom
                left_margin = 72  # 1 inch from the left
                right_margin = 72  # 1 inch from the right
                available_height = printer.pageRect().height() - top_margin - bottom_margin

                # border_height = available_height / 2
                border_height = 72

                # Define font and font size
                font = QFont("Arial", 12)  # Adjust font size here
                painter.setFont(font)

                # Define line height (font size + extra space)
                line_height = font.pointSize() + 10  # Adjust extra space as needed

                # Define text color
                text_color = Qt.white

                # -----------------------------------------------------------------------------------------

                # Load your background image
                bg_image = QImage("background.jpg")

                # Set the size you want for the background image
                target_width = 800
                target_height = 1200
                bg_image = bg_image.scaled(target_width, target_height)

                # Calculate the position to center the image on the page
                a_position = (printer.pageRect().width() - bg_image.width()) / 2
                b_position = (printer.pageRect().height() - bg_image.height()) / 2

                # Draw the background image
                painter.drawImage(a_position, b_position, bg_image)

                # -----------------------------------------------------------------------------------------

                title = "Cyber Vision "  # Define your title

                # Calculate the position for the title (adjust as needed)
                # title_x = left_margin
                # title_y = right_margin // 4
                # --------------------------
                font = QFont("Palatino Linotype", 12)  # Define the font
                fontMetrics = QFontMetrics(font)
                title_width = fontMetrics.width(title)  # Calculate the width of the title text
                title_x = printer.pageRect().width() - right_margin - title_width  # Calculate the x-coordinate
                title_y = top_margin + fontMetrics.height()
                # --------------------------

                # Combine all the text with increased font size and spaces
                # information_label_text = f"\n\n\nModel's Prediction :\n {information_text}\n\n\nFile Details : \n{details_text}\n\n\n{dlls_text}\n\n\n{apis_text}\n\n\n{strings_text}\n\n\n\n{disassemble_text}"
                information_label_text = f"\n\n\nModel's Prediction :\n {information_text}\n\n\nFile Details : \n{details_text}\n\n\n{dlls_text}\n\n\n{apis_text}\n\n\n{strings_text}\n\n"

                # Split the text into lines
                lines = information_label_text.split('\n')

                # Draw logo and title on every page
                y_position = top_margin + border_height  # Increase the y_position
                for line in lines:
                    if y_position + line_height > available_height:
                        printer.newPage()
                        y_position = top_margin + border_height  # Reset y_position on new page

                        # Draw your background image
                        # painter.drawImage(printer.pageRect(), bg_image)
                        # Draw the background image
                        # self.draw_background_image(painter, printer)
                        # -----------------------------------------------------------------------------------------

                        # Load your background image
                        bg_image = QImage("background.jpg")

                        # Set the size you want for the background image
                        target_width = 800
                        target_height = 1200
                        bg_image = bg_image.scaled(target_width, target_height)

                        # Calculate the position to center the image on the page
                        a_position = (printer.pageRect().width() - bg_image.width()) / 2
                        b_position = (printer.pageRect().height() - bg_image.height()) / 2

                        # Draw the background image
                        painter.drawImage(a_position, b_position, bg_image)

                        # -----------------------------------------------------------------------------------------

                    # Draw logo
                    # logo_path = "logoone.png"
                    # logo_image = QImage(logo_path)
                    # logo_rect = QRectF(left_margin, top_margin / 2, logo_image.width() / 4, logo_image.height() / 4)
                    # painter.drawImage(logo_rect, logo_image)

                    # Draw title
                    title_color = Qt.red  # Define your desired color
                    painter.setPen(QPen(title_color))
                    painter.drawText(title_x, title_y, title)

                    # Draw red line
                    red_pen = QPen(Qt.red)
                    painter.setPen(red_pen)
                    # painter.drawLine(int(left_margin), int(top_margin + logo_rect.height() / 4 + 10),
                    #                  int(printer.pageRect().width() - right_margin),
                    #                  int(top_margin + logo_rect.height() / 4 + 10))

                    # # Draw title
                    # painter.drawText(title_x, title_y, title)

                    # Draw content line
                    painter.setPen(QPen(text_color))
                    painter.drawText(left_margin, y_position, line)
                    # y_position += line_height + line_height  # Increase y_position by two line heights for the gap
                    y_position += line_height

                painter.end()

        except Exception as e:
            print(f"Error generating report: {e}")

    def split_text(self, text, max_height, font_metrics):
        words = text.split()
        lines = ['']
        for word in words:
            if font_metrics.boundingRect(lines[-1] + ' ' + word).height() < max_height:
                lines[-1] += ' ' + word
            else:
                lines.append(word)
        return lines


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
