#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
Author Stuff Incoming
"""

import sys
import PySide2.QtWidgets as qt
import PySide2.QtGui as gui

class Window(qt.QWidget):
    def __init__(self):
        super().__init__()
        
        self.initUI()
        
        
    def initUI(self):
        
        self.resize(750, 500)        
        header = qt.QHBoxLayout()
        container = qt.QHBoxLayout()

        qt.QToolTip.setFont(gui.QFont('SansSerif', 10))
        
        #self.setToolTip('This is a <b>QWidget</b> widget')
    
        btn = qt.QPushButton('File Crypter', self)
        btn.resize(150,150)
        btn.move(150, 200)
        pic = qt.QLabel(self)
        pic.setPixmap(gui.QPixmap("document.png"))
        pic.move(200,200)
        pwd = qt.QLabel('<kryptoQt>',self)
        pwd.move(50,20)     
        pwd.setToolTip('This is an <b>openssl</b> GUI app.')
        header.addWidget(pwd)
        container.addWidget(btn)
        
        self.setWindowTitle('kryptoQt')    

    def closeEvent(self, event):
        
        reply = qt.QMessageBox.question(self, 'Message',
            "Are you sure to quit?", qt.QMessageBox.Yes | 
            qt.QMessageBox.No, qt.QMessageBox.No)

        if reply == qt.QMessageBox.Yes:
            event.accept()
        else:
            event.ignore()        
        

if __name__ == '__main__':
    
    app = qt.QApplication(sys.argv)

    window = Window()

    window.show()
    
    sys.exit(app.exec_())