# NetworkPacketCapture
Network packet capture (libpcap)

- Commands -> make all

- Uygulama argümanları -d(device) -f(file) -s(filter) expression

Argümanlar: 
- -d device-> anlık olarak ağdan paket yakalamak için ağ arayüz ismi (enp0s3,enp0s25,eth0,vb.)
- -f file-> tcpdump formatındaki dosyadan paket okumak için.
- -s filter expression-> herhangi bir filtre verilmez ise ağ üzerindeki tüm paketler gösterilir. İfade olması durumunda yanlızca eşleşenler gösterilir.
              
Örnek Kullanım:

sudo ./a.out -d enp0s3 -> ağ üzerindeki tüm paketler gösterilir.

sudo ./a.out -d enp0s3 -s github.com -> ping github.com

sudo ./a.out -d enps3 -s ubuntu port 53 -> (BPF filter)

Yakalanan paketlerden Ethernet type, packet len, protocol, ethernet src, ethernet dst, ip src, ip dst, src port, dst port değerleri gösterilir.

- Manuel

sudo apt-get install libpcap-dev

g++ -o main.o main.cpp -lpcap

sudo ./main.o d(device) -f(file) -s(filter) expression

(sudo setcap cap_net_raw,cap_net_admin = eip myapplication) uygulamayı root olarak çalıştırmak için

- Kaynaklar:

- https://www.tcpdump.org/
- https://www.tcpdump.org/pcap.html
- http://yuba.stanford.edu/~casado/pcap/section3.html
- https://yazilimcorbasi.blogspot.com/2015/04/libpcap.html
- https://github.com/vhok74/network_packet_capture/blob/master/main.cpp
- https://github.com/SelinaDeepKaur/Passive-Network-Monitor
