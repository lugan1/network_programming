# coding: utf-8
import subprocess
import os
import sys
from PyQt5 import QtWidgets
from PyQt5 import QtGui
from PyQt5 import uic
from PyQt5 import QtCore
from PyQt5.QtCore import pyqtSlot
from PyQt5.QtWidgets import *
import socket
iptlist = ["iptables","-A","INPUT","-p","프로토콜","--dport","포트번호","-s","소스","-j","ACCEPT","서비스","--icmp-type","icmp종류"]
#              0        1       2       3       4           5       6       7     8     9     10    11         12         13          14            15            16
table = [iptlist[1],iptlist[11],iptlist[4],iptlist[6],iptlist[8],iptlist[10]]
#           0            1           2          3        4          5

global string, row, sume
string = ""
row = 0
sume = ["0"]
def combine(index, value):
    iptlist[index] = value

def getsume():
    return int(sume[0])

def setsume(row):
    sume[0] = str(row)


class MainWindow(QMainWindow):
    def __init__(self, parent=None):
        QtWidgets.QDialog.__init__(self, parent)
        self.ui = uic.loadUi("test2.ui", self)
        #파이선파일하고 ui 파일하고 직접 연결
        header = self.tableWidget.horizontalHeader()
        header.setSectionResizeMode(3, QtWidgets.QHeaderView.ResizeToContents)
        self.accept.clicked.connect(self.accept_change)
        #이벤트(cliked) <= 이벤트 처리함수 연결
        self.fileopen.clicked.connect(self.fileopen_clicked)
        self.filesave.clicked.connect(self.filesave_clicked)
        self.bt_ctrule.clicked.connect(self.bt_ctrule_clicked)
        self.iptable_L.clicked.connect(self.iptable_L_clicked)
        self.iptable_F.clicked.connect(self.iptable_F_clicked)
        self.ruleaccept.clicked.connect(self.ruleaccept_clicked)
        self.tableclear.clicked.connect(self.tableclear_clicked)
        self.btflagcut.clicked.connect(self.btflagcut_clicked)
        self.btflagcutdel.clicked.connect(self.btflagcutdel_clicked)
        self.btpvipcut.clicked.connect(self.btpvipcut_clicked)
        self.btpvipcutdel.clicked.connect(self.btpvipcutdel_clicked)
        self.btallcut.clicked.connect(self.btallcut_clicked)
        self.btallcutdel.clicked.connect(self.btallcutdel_clicked)
        self.ui.show()
        self.Csource.activated[str].connect(self.changeSource)
        self.Ccmd.activated[str].connect(self.changeCmd)
        self.Cservice.activated[str].connect(self.changeService)
        self.Cdecision.activated[str].connect(self.changeDecision)
        self.Cicmptype.activated[str].connect(self.changeicmptype)



    def changeService(self, text):
        if text == "사용자지정TCP규칙":
            protocol = "TCP"
            port = ""
            self.Tprotocol.setText(protocol)
            self.Tport.setText(port)
            combine(4,protocol)
            combine(6,port)
            combine(11, text)
        if text == "사용자지정UDP규칙":
            protocol = "UDP"
            port = ""
            self.Tprotocol.setText(protocol)
            self.Tport.setText(port)
            combine(4,protocol)
            combine(6,port)
            combine(11, text)
        if text == "사용자지정프로토콜":
            protocol = ""
            port = "0:65535"
            self.Tprotocol.setText(protocol)
            self.Tport.setText(port)
            combine(4,protocol)
            combine(6,port)
            combine(11, text)
        if text == "모든TCP":
            protocol = "TCP"
            port = "0:65535"
            source = "0.0.0.0/0"
            self.Tprotocol.setText(protocol)
            self.Tport.setText(port)
            self.Tsource.setText(source)
            combine(4,protocol)
            combine(6,port)
            combine(8,source)
            combine(11, text)
        if text == "모든UDP":
            protocol = "UDP"
            port = "0:65535"
            source = "0.0.0.0/0"
            self.Tprotocol.setText(protocol)
            self.Tport.setText(port)
            self.Tsource.setText(source)
            combine(4,protocol)
            combine(6,port)
            combine(8,source)
            combine(11, text)
        if text == "ICMP":
            protocol = "ICMP"
            port = ""
            source = "0.0.0.0/0"
            self.Tprotocol.setText(protocol)
            self.Tport.setText(port)
            self.Tsource.setText(source)
            combine(4,protocol)
            combine(6,port)
            combine(8,source)
            combine(11, text)
        if text == "모든ICMP-IPv6":
            protocol = "IPV6 ICMP"
            port = "0:65535"
            source = "0.0.0.0/0"
            self.Tprotocol.setText(protocol)
            self.Tport.setText(port)
            combine(4,protocol)
            combine(6,port)
            combine(8,source)
            combine(11, text)
        if text == "모든트래픽":
            protocol = "모두"
            port = "0:65535"
            source = "0.0.0.0/0"
            self.Tprotocol.setText(protocol)
            self.Tport.setText(port)
            self.Tsource.setText(source)
            combine(4,protocol)
            combine(6,port)
            combine(8,source)
            combine(11, text)
        if text == "SSH":
            protocol = "TCP"
            port = "22"
            self.Tprotocol.setText(protocol)
            self.Tport.setText(port)
            combine(4,protocol)
            combine(6,port)
            combine(11, text)
        if text == "SMTP":
            protocol = "TCP"
            port = "25"
            self.Tprotocol.setText(protocol)
            self.Tport.setText(port)
            combine(4,protocol)
            combine(6,port)
            combine(11, text)
        if text == "HTTP":
            protocol = "TCP"
            port = "80"
            self.Tprotocol.setText(protocol)
            self.Tport.setText(port)
            combine(4,protocol)
            combine(6,port)
            combine(11, text)
        if text == "POP3":
            protocol = "TCP"
            port = "110"
            self.Tprotocol.setText(protocol)
            self.Tport.setText(port)
            combine(4,protocol)
            combine(6,port)
            combine(11, text)
        if text == "IMAP":
            protocol = "TCP"
            port = "143"
            self.Tprotocol.setText(protocol)
            self.Tport.setText(port)
            combine(4,protocol)
            combine(6,port)
            combine(11, text)
        if text == "DNS(UDP)":
            protocol = "UDP"
            port = "53"
            self.Tprotocol.setText(protocol)
            self.Tport.setText(port)
            combine(4,protocol)
            combine(6,port)
            combine(11, text)
        if text == "DNS(TCP)":
            protocol = "TCP"
            port = "53"
            self.Tprotocol.setText(protocol)
            self.Tport.setText(port)
            combine(4,protocol)
            combine(6,port)
            combine(11, text)
        if text == "Telnet":
            protocol = "TCP"
            port = "23"
            self.Tprotocol.setText(protocol)
            self.Tport.setText(port)
            combine(4,protocol)
            combine(6,port)
            combine(11, text)
        if text == "TFTP":
            protocol = "TCP"
            port = "69"
            self.Tprotocol.setText(protocol)
            self.Tport.setText(port)
            combine(4, protocol)
            combine(6, port)
            combine(11, text)
        if text == "FTP":
            protocol = "TCP"
            port = "21"
            self.Tprotocol.setText(protocol)
            self.Tport.setText(port)
            combine(4,protocol)
            combine(6,port)
            combine(11, text)
        if text == "SNMP":
            protocol = "TCP"
            port = "161"
            self.Tprotocol.setText(protocol)
            self.Tport.setText(port)
            combine(4,protocol)
            combine(6,port)
            combine(11, text)


    def changeDecision(self, text):
        if text == "허용":
            decision = "ACCEPT"
            combine(10,decision)
        if text == "거부":
            decision = "DROP"
            combine(10,decision)

    def changeCmd(self, text):
        if text == "추가":
            cmd = "-A"
            combine(1,cmd)
        if text == "삭제":
            cmd = "-D"
            combine(1,cmd)

    def changeSource(self, text):
        source = ""
        if text == "위치무관":
            source = '0.0.0.0/0'
            self.Tsource.setText(source)
            combine(8, source)

        if text == "내IP":
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8',1))
            source = s.getsockname()[0]
            self.Tsource.setText(str(source))
            combine(8, source)

        if text == "사용자지정":
            self.Tsource.setText("")
            combine(8, source)

    def changeicmptype(self, text):
        if text == "echo-reply":
            icmptype = text
            combine(13,text)
        elif text == "destination-unreachable":
            icmptype = text
            combine(13,text)
        elif text == "redirect":
            icmptype = text
            combine(13,text)
        elif text == "echo-request":
            icmptype = text
            combine(13,text)
        elif text == "time-exceeded":
            combine(13,text)
            icmptype = text
        print(icmptype)


    @pyqtSlot()
    def bt_ctrule_clicked(self):
        #iptables = ["iptables", "명령어", "INPUT", "-p", "프로토콜", "--dport", "포트번호", "-s", "소스", "-j", "결정"]
        iptlist[4] = self.Tprotocol.text()
        iptlist[6] = self.Tport.text()
        iptlist[8] = self.Tsource.text()

        table[0] = iptlist[1]
        table[1] = iptlist[11]
        table[2] = iptlist[4]
        table[3] = iptlist[6]
        table[4] = iptlist[8]
        table[5] = iptlist[10]


        if table[0] == "-A":
            table[0] = "추가"
        elif table[0] == "-D":
            table[0] = "삭제"

        if table[5] == "ACCEPT":
            table[5] = "허용"
        elif table[5] == "DROP":
            table[5] = "차단"

        if table[1] =="사용자지정TCP규칙":
            table[1] = "커스텀TCP"
        elif table[1] == "사용자지정UDP규칙":
            table[1] = "커스텀UDP"

        if table[2] =="ICMP":
            table[3] = iptlist[13]

        row = getsume()
        rowPosition = self.tableWidget.rowCount()
        self.tableWidget.insertRow(rowPosition)
        for i in range(6):
           item = QTableWidgetItem(table[i])
           # 테이블에 넣을 값 객체로 생성
           self.tableWidget.setItem(row,i,item)
           # 테이블에 아이템객체 삽입

        row = row +1
        setsume(row)



        temp = ["iptables", "-A", "INPUT", "-P", "프로토콜", "--dport", "포트번호", "-s", "소스",  "-j", "ACCEPT"]
        #             0       1     2         3     4          5            6         7    8       9      10
        for i in range(11):
            temp[i] = iptlist[i]

        if temp[4] == "ICMP":
            temp[5] = "--icmp-type"
            temp[6] = iptlist[13]

        input = " ".join(temp)

        text = self.consol.toPlainText() +'\n'+ input
        self.consol.setPlainText(text)

    @pyqtSlot()
    def fileopen_clicked(self):
        fname = QFileDialog.getOpenFileName(self)
        load = 'iptables-restore < '+fname[0]
        result = subprocess.call(load, shell=True, universal_newlines=True, stderr=subprocess.STDOUT)
        L = 'iptables -L --line-numbers'
        show = subprocess.check_output(L, shell=True, universal_newlines=True, stderr=subprocess.STDOUT)
        self.tbview.setPlainText(str(show))
        #fname[0] 파일 경로

    @pyqtSlot()
    def filesave_clicked(self):
        save = 'iptables-save > /home/leehoogy/iptables.rules'
        result = subprocess.call(save, shell=True, universal_newlines=True, stderr=subprocess.STDOUT)
        QMessageBox.about(self,"messege box","save complite.")

    @pyqtSlot()
    def iptable_L_clicked(self):
        L = 'iptables -L --line-numbers'
        result = subprocess.check_output(L, shell=True, universal_newlines=True, stderr=subprocess.STDOUT)
        self.tbview.setPlainText(str(result))

    @pyqtSlot()
    def iptable_F_clicked(self):
        F = 'iptables -F'
        result = subprocess.call(F, shell=True, universal_newlines=True, stderr=subprocess.STDOUT)
        L = 'iptables -L --line-numbers'
        show = subprocess.check_output(L, shell=True, universal_newlines=True, stderr=subprocess.STDOUT)
        self.tbview.setPlainText(str(show))

    @pyqtSlot()
    def ruleaccept_clicked(self):
        text = self.consol.toPlainText()
        result = subprocess.call(text, shell=True, universal_newlines=True, stderr=subprocess.STDOUT)
        L = 'iptables -L --line-numbers'
        show = subprocess.check_output(L, shell=True, universal_newlines=True, stderr=subprocess.STDOUT)
        self.tbview.setPlainText(str(show))

    @pyqtSlot()
    def tableclear_clicked(self):
        while (self.tableWidget.rowCount() > 0):
            {
                self.tableWidget.removeRow(0)
            }
        row = 0
        setsume(row)
        self.consol.setPlainText("")

    @pyqtSlot()
    def accept_change(self):
        text = self.lineEdit.text()
        test = subprocess.check_output(text, shell=True, universal_newlines=True, stderr=subprocess.STDOUT)
        self.tbview.setPlainText(str(test))

    @pyqtSlot()
    def btflagcut_clicked(self):
        flagcut = "iptables -A INPUT -p TCP --tcp-flags ACK,FIN FIN -j DROP\n" \
                  "iptables -A INPUT -p TCP --tcp-flags ALL NONE -j DROP\n" \
                  "iptables -A INPUT -p TCP --tcp-flags ALL PSH,FIN -j DROP\n" \
                  "iptables -A INPUT -p TCP --tcp-flags ALL URG,PSH,FIN -j DROP\n" \
                  "iptables -A INPUT -p TCP --tcp-flags ALL SYN,ACK,FIN -j DROP\n" \
                  "iptables -A INPUT -p TCP --tcp-flags ALL SYN,FIN,PSH -j DROP\n" \
                  "iptables -A INPUT -p TCP --tcp-flags ALL SYN,FIN,RST -j DROP\n" \
                  "iptables -A INPUT -p TCP --tcp-flags ALL SYN,FIN,RST,PSH -j DROP\n" \
                  "iptables -A INPUT -p TCP --tcp-flags ALL SYN,FIN,ACK,RST -j DROP\n" \
                  "iptables -A INPUT -p TCP --tcp-flags ALL SYN,ACK,FIN,RST,PSH -j DROP\n" \
                  "iptables -A INPUT -p TCP --tcp-flags FIN,RST FIN,RST -j DROP\n" \
                  "iptables -A INPUT -p TCP --tcp-flags SYN,FIN SYN,FIN -j DROP\n" \
                  "iptables -A INPUT -p TCP --tcp-flags ACK,PSH PSH -j DROP\n" \
                  "iptables -A INPUT -p TCP --tcp-flags ACK,URG URG -j DROP"
        print(flagcut)
        text = self.consol.toPlainText()
        text = text+"\n"+flagcut
        self.consol.setPlainText(text)

    @pyqtSlot()
    def btflagcutdel_clicked(self):
        flagcutdel = "iptables -D INPUT -p TCP --tcp-flags ACK,FIN FIN -j DROP\n" \
                     "iptables -D INPUT -p TCP --tcp-flags ALL NONE -j DROP\n" \
                     "iptables -D INPUT -p TCP --tcp-flags ALL PSH,FIN -j DROP\n" \
                     "iptables -D INPUT -p TCP --tcp-flags ALL URG,PSH,FIN -j DROP\n" \
                     "iptables -D INPUT -p TCP --tcp-flags ALL SYN,ACK,FIN -j DROP\n" \
                     "iptables -D INPUT -p TCP --tcp-flags ALL SYN,FIN,PSH -j DROP\n" \
                     "iptables -D INPUT -p TCP --tcp-flags ALL SYN,FIN,RST -j DROP\n" \
                     "iptables -D INPUT -p TCP --tcp-flags ALL SYN,FIN,RST,PSH -j DROP\n" \
                     "iptables -D INPUT -p TCP --tcp-flags ALL SYN,FIN,ACK,RST -j DROP\n" \
                     "iptables -D INPUT -p TCP --tcp-flags ALL SYN,ACK,FIN,RST,PSH -j DROP\n" \
                     "iptables -D INPUT -p TCP --tcp-flags FIN,RST FIN,RST -j DROP\n" \
                     "iptables -D INPUT -p TCP --tcp-flags SYN,FIN SYN,FIN -j DROP\n" \
                     "iptables -D INPUT -p TCP --tcp-flags ACK,PSH PSH -j DROP\n" \
                     "iptables -D INPUT -p TCP --tcp-flags ACK,URG URG -j DROP"
        print(flagcutdel)
        text = self.consol.toPlainText()
        text = text + "\n" + flagcutdel
        self.consol.setPlainText(text)

    @pyqtSlot()
    def btpvipcut_clicked(self):
        pvipcut = "iptables -A INPUT -i eth0 -s 10.0.0.0/8 -j DROP\n" \
                  "iptables -A INPUT -i eth0 -s 172.16.0.0/12 -j DROP\n" \
                  "iptables -A INPUT -i eth0 -s 192.168.0.0/16 -j DROP\n" \
                  "iptables -A INPUT -i eth0 -s 224.0.0.0/4 -j DROP\n" \
                  "iptables -A INPUT -i eth0 -s 240.0.0.0/5 -j DROP"
        print(pvipcut)
        text = self.consol.toPlainText()
        text = text + "\n" + pvipcut
        self.consol.setPlainText(text)

    @pyqtSlot()
    def btpvipcutdel_clicked(self):
        pvipcut = "iptables -D INPUT -i eth0 -s 10.0.0.0/8 -j DROP\n" \
                  "iptables -D INPUT -i eth0 -s 172.16.0.0/12 -j DROP\n" \
                  "iptables -D INPUT -i eth0 -s 192.168.0.0/16 -j DROP\n" \
                  "iptables -D INPUT -i eth0 -s 224.0.0.0/4 -j DROP\n" \
                  "iptables -D INPUT -i eth0 -s 240.0.0.0/5 -j DROP"
        print(pvipcut)
        text = self.consol.toPlainText()
        text = text + "\n" + pvipcut
        self.consol.setPlainText(text)

    def btallcut_clicked(self):
        allcut = "iptables -A INPUT -j DROP"
        print(allcut)
        text = self.consol.toPlainText()
        text = text + "\n" + allcut
        self.consol.setPlainText(text)

    def btallcutdel_clicked(self):
        allcut = "iptables -D INPUT -j DROP"
        print(allcut)
        text = self.consol.toPlainText()
        text = text + "\n" + allcut
        self.consol.setPlainText(text)

if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    mainwindow = MainWindow()
    app.exec()