from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.label import Label
import nmap

class NmapScanner(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(orientation='vertical', **kwargs)

        self.ip_input = TextInput(hint_text='Enter IP address (e.g., 192.168.56.1)', multiline=False)
        self.port_input = TextInput(hint_text='Enter port range (e.g., 20-1000)', multiline=False)
        self.scan_button = Button(text='Start Scan')
        self.result_label = Label(text='Scan results will appear here.', halign='left', valign='top')
        self.result_label.bind(size=self.result_label.setter('text_size'))

        self.scan_button.bind(on_press=self.run_scan)

        self.add_widget(self.ip_input)
        self.add_widget(self.port_input)
        self.add_widget(self.scan_button)
        self.add_widget(self.result_label)

    def run_scan(self, instance):
        target = self.ip_input.text.strip()
        ports = self.port_input.text.strip() or "1-1024"
        ports = ports.replace(" ", "")

        try:
            nm = nmap.PortScanner()
            self.result_label.text = f"Scanning {target} on ports {ports}...\n"
            nm.scan(hosts=target, ports=ports)

            if not nm.all_hosts():
                self.result_label.text += "No hosts found. Check IP or network."
                return

            for host in nm.all_hosts():
                self.result_label.text += f"\nHost: {host} ({nm[host].hostname()})\n"
                self.result_label.text += f"Status: {nm[host].state()}\n"
                if 'tcp' in nm[host]:
                    self.result_label.text += "TCP Ports:\n"
                    for port in sorted(nm[host]['tcp']):
                        state = nm[host]['tcp'][port]['state']
                        self.result_label.text += f"  Port {port}: {state}\n"
                else:
                    self.result_label.text += "No TCP ports found.\n"

        except Exception as e:
            self.result_label.text = f"Error: {str(e)}"

class NmapApp(App):
    def build(self):
        return NmapScanner()

if __name__ == '__main__':
    NmapApp().run()