import tkinter as tk
from functools import partial  
import nmap3
import scapy
from scapy.all import *




class Application(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self.pack()
        self.create_widgets()


    def create_widgets(self):
        

        self.labelResult = tk.Label(self)
        self.labelResult.pack(side="bottom")

        self.labelIP= tk.Label(self)
        self.labelIP["text"] = "IP:"
        self.labelIP.pack(padx=5, pady=10,side="left")

        ipValue = tk.StringVar(value="0.0.0.0")
        self.ip = tk.Entry(self,textvariable=ipValue)
        self.ip.place(x = 80, y = 50) 
        self.ip.pack(side="left")


        self.labelIP= tk.Label(self)
        self.labelIP["text"] = "         Protocolo:" 
        self.labelIP.pack(padx=5, pady=10,side="left")

        Proto=tk.StringVar(value="Ambos")
        self.TCPswitch = tk.Radiobutton(self, text="TCP", indicatoron=True, variable=Proto,value="TCP")
        self.TCPswitch.pack(side="left")
        self.UDPswitch = tk.Radiobutton(self, text="UDP", indicatoron=True, variable=Proto,value="UDP")
        self.UDPswitch.pack(side="left")
        self.UDPswitch = tk.Radiobutton(self, text="Ambos", indicatoron=True, variable=Proto,value="Ambos")
        self.UDPswitch.pack(side="left")

        self.labelIP= tk.Label(self)
        self.labelIP["text"] = "         " 
        self.labelIP.pack(padx=5, pady=10,side="left")

        Modo=tk.StringVar(value="Unico")
        self.TCPswitch = tk.Radiobutton(self, text="Escanear Unico host", indicatoron=True, variable=Modo,value="Unico")
        self.TCPswitch.pack(side="left")
        self.UDPswitch = tk.Radiobutton(self, text="Escanear Rede", indicatoron=True, variable=Modo,value="Range")
        self.UDPswitch.pack(side="left")



        ports=tk.StringVar(value="*")
        self.labelIP= tk.Label(self)
        self.labelIP["text"] = "         Range de Portas:" 
        self.labelIP.pack(padx=5, pady=10,side="left")
        self.portr = tk.Entry(self,textvariable=ports)
        self.portr.pack(side="left")


        runi = partial(self.run, ipValue,Proto,ports,self.labelResult,Modo)  

        self.start = tk.Button(self)
        self.start["text"] = "Run"
        self.start["command"] = runi
        self.start.pack(side="bottom")

        topsport = partial(self.top_ports, ipValue,self.labelResult,Modo)  

        self.tops = tk.Button(self)
        self.tops["text"] = "Scan top ports"
        self.tops["command"] = topsport
        self.tops.pack(side="bottom")


    def top_ports(self,ip,result,modo):
        ipv=(ip.get())
        modo=(modo.get())
        nmap = nmap3.Nmap()

        if modo=="Unico":
            results= nmap.scan_top_ports(ipv) 
            result=""
            for i in results:
                result = result + "\n" + ("Porta" + " " + i['port'] + " - "  + "Protocolo: "+ i['protocol'] + " - " + i['state'] + " - " + i['service']['name'])
            self.labelResult.config(text=result,font=("Courier", 18))
        else:
            arp = ARP(pdst=ipv)
            ether = scapy.layers.l2.Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            result = srp(packet, timeout=3)[0]
            clients = []
            for sent, received in result:
                clients.append(received.psrc)
            result=""
            #print(clients)
            for j in clients:
                results= nmap.scan_top_ports(j)

                for i in results:
                    if i['state']=='open':
                            result = result + "\n" + "IP:"+ j + " " + ("Porta" + " " + i['port'] + " - "  + "Protocolo: "+ i['protocol'] + " - " + i['state'] + " - " + i['service']['name'])    

            self.labelResult.config(text=result,font=("Courier", 18))


    def run(self,ip,protocol,portas,result,modo):
        ipv=(ip.get())
        protocolo=(protocol.get())
        rangeport=(portas.get())
        mode=(modo.get())

        if not rangeport.isdigit():
            portas=rangeport.split(",")
            listaPortas=portas.copy()
            
            for i in portas:
                
                if (":" in i):
                    listaPortas.remove(i)
                    varias=i.split(":")
                    listaPortas +=  (list(range(int(varias[0]),(int(varias[1])+1))))
                if("-" in i):
                    listaPortas.remove(i)
                    varias=i.split("-")
                    listaPortas +=  (list(range(int(varias[0]),(int(varias[1])+1))))
        else:
            listaPortas=[int(rangeport)]
        for i in range(len(listaPortas)):
            listaPortas[i]=int(listaPortas[i])

        if mode=="Unico":
            if protocolo=="TCP":
                result=""
                for p in listaPortas:
                    pong = sr1(IP(dst=ipv)/TCP(sport=RandShort(), dport=p, flags="S"), timeout=1, verbose=0)
                    if pong != None:
                        if pong[TCP].flags == 'SA':
                            result += "\n" + ("Porta" + ": " + str(p) + ' Open')            
                self.labelResult.config(text=result,font=("Courier", 18))  

            elif protocolo=="UDP":
                result=""
                for p in listaPortas:
                    pongi = sr1(IP(dst=ipv)/UDP(sport=p, dport=p), timeout=2, verbose=0)

                    if pongi == None:
                        result += "\n" + ("Porta" + ": " + str(p) + ' "Open / filtered"')    
                    elif pongi.haslayer(UDP):
                        result += "\n" + ("Porta" + ": " + str(p) + ' "Open / filtered"')            
                self.labelResult.config(text=result,font=("Courier", 10))  

            else:
                result=""
                for p in listaPortas:
                    pong = sr1(IP(dst=ipv)/TCP(sport=RandShort(), dport=p, flags="S"), timeout=1, verbose=0)
                    if pong != None:
                        if pong[TCP].flags == 'SA':
                            result += "\n" + ("Porta" + ": " + str(p) + '  Open'+ '   Protocolo: TCP')  
                    pongi = sr1(IP(dst=ipv)/UDP(sport=p, dport=p), timeout=2, verbose=0)
                    if pongi == None:
                        result += "\n" + ("Porta" + ": " + str(p) + ' "Open / filtered"'+ '   Protocolo: UDP')               
                    elif pongi.haslayer(UDP):
                        result += "\n" + ("Porta" + ": " + str(p) + ' "Open / filtered"'+ '   Protocolo: UDP')                            
                self.labelResult.config(text=result,font=("Courier", 18))  
        else:
            arp = ARP(pdst=ipv)
            ether = scapy.layers.l2.Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            result = srp(packet, timeout=3)[0]
            clients = []            
            for sent, received in result:
                clients.append(received.psrc)
            
            if protocolo=="TCP":
                result=""
                for j in clients:
                    for p in listaPortas:
                        pong = sr1(IP(dst=j)/TCP(sport=RandShort(), dport=p, flags="S"), timeout=1, verbose=0)
                        if pong != None:
                            if pong[TCP].flags == 'SA':
                                result += "\n" "IP:" + j + ("   Porta" + ": " + str(p) + ' open')            
                self.labelResult.config(text=result,font=("Courier", 18))

            elif protocolo=="UDP":
                result=""
                for j in clients:
                    for p in listaPortas:
                        pongi = sr1(IP(dst=j)/UDP(sport=p, dport=p), timeout=2, verbose=0)
                        if pongi == None or pongi.haslayer(UDP):
                            result += "\n" + "IP: " + j + ("  Porta" + ": " + str(p) + ' "Open / filtered"'+ '   Protocolo: UDP')            
                self.labelResult.config(text=result,font=("Courier", 18))  

            else:

                result=""
                for j in clients:
                    for p in listaPortas:
                        pong = sr1(IP(dst=j)/TCP(sport=RandShort(), dport=p, flags="S"), timeout=1, verbose=0)
                        if pong != None:
                            if pong[TCP].flags == 'SA':
                                result += "\n" + "IP: " + j + ("   Porta" + ": " + str(p) + ' open' + '   Protocolo: TCP')  
                        pongi = sr1(IP(dst=j)/UDP(sport=p, dport=p), timeout=2, verbose=0)
                        if pongi == None:
                            result += "\n" + "IP: " + j + ("   Porta" + ": " + str(p) + ' "Open / filtered"'+ '   Protocolo: UDP')    
                        elif pongi.haslayer(UDP):
                            result += "\n" + "IP: " + j + ("   Porta" + ": " + str(p) + ' "Open / filtered"'+ '   Protocolo: UDP')   
                self.labelResult.config(text=result,font=("Courier", 18))
                pass

root = tk.Tk()
root.title('Port-Scaner')  

app = Application(master=root)
 
app.mainloop()