# tp-unlink

enable root access on türk telekom tp-link ex20v routers via CWMP/TR-069

spoofs dhcp option 43 to redirect the router to a fake acs. Sets TR-069 parameters to enable ssh, telnet, http, and https access with your password

works on türk telekom firmware. other isp variants untested

## requirements

- direct ethernet connection to router's LAN port
- admin/root privileges on your machine
- router must have cwmp enabled (factory default)

## build

```
win: cl /O2 tp-unlink.c ws2_32.lib iphlpapi.lib shell32.lib
     gcc -O2 -o tp-unlink.exe tp-unlink.c -lws2_32 -liphlpapi -lshell32
nix: cc -std=c11 -O2 -o tp-unlink tp-unlink.c -lpthread
```

## usage

```
tp-unlink [options] <password>

  -i <iface>   network interface
  -S <ip>      server IP (default 10.116.13.100)
  -C <ip>      client IP (default 10.116.13.20)
  -p <port>    ACS port (default 7547)
  -t <sec>     timeout (default 30)
  -s <slot>    user slot (default 2)
  -b <file>    backup filename
  -d           disable root access
  -x           keep CWMP enabled
  -n           dry run
  -v           verbose
  -V           version
```

## quick start

```sh
# windows (admin cmd)
tp-unlink.exe mypassword

# linux
sudo ./tp-unlink mypassword
```

after success, connect via ssh/telnet to 192.168.1.1 with your password

## how it works

1. assigns itself an ip in the 10.116.13.0/24 range
2. responds to router's dhcp requests with option 43 containing fake acs url
3. router connects to fake acs for TR-069 provisioning
4. tool sends SetParameterValues to enable root user and set protocols
5. disables cwmp to prevent isp from reverting changes

current settings are backed up to `backup_YYYYMMDD_HHMMSS.xml` before modification

## return codes

| code | meaning           |
|------|-------------------|
| 0    | success           |
| 1    | error             |
| 2    | timeout (no dhcp) |
| 3    | network error     |
| 4    | already enabled   |

## undo

```sh
tp-unlink -d
```

## notes

- disconnect WAN before running
- some routers require reboot after
- VLAN detection will abort if tagged traffic seen

---

# tp-unlink (Türkçe)

türk telekom TP-Link EX20v modemlerde root erişimi açar. CWMP/TR-069 protokolü üzerinden çalışır

dchp option 43 ile sahte acs sunucusu gösterir. TR-069 parametrelerini değiştirerek ssh, telnet, http ve https erişimini etkinleştirir

türk telekom donanımı için yazıldı. diğer iss sürümleri test edilmedi.

## gereksinimler

- modem LAN portuna doğrudan ethernet bağlantısı
- bilgisayarda yönetici/root yetkisi
- modemde CWMP aktif olmalı (fabrika ayarı)

## derleme

```
win: cl /O2 tp-unlink.c ws2_32.lib iphlpapi.lib shell32.lib
     gcc -O2 -o tp-unlink.exe tp-unlink.c -lws2_32 -liphlpapi -lshell32
nix: cc -std=c11 -O2 -o tp-unlink tp-unlink.c -lpthread
```

## kullanım

```
tp-unlink [seçenekler] <şifre>

  -i <arayüz>  ağ arayüzü
  -S <ip>      sunucu IP (varsayılan 10.116.13.100)
  -C <ip>      istemci IP (varsayılan 10.116.13.20)
  -p <port>    ACS portu (varsayılan 7547)
  -t <sn>      zaman aşımı (varsayılan 30)
  -s <slot>    kullanıcı slotu (varsayılan 2)
  -b <dosya>   yedek dosya adı
  -d           root erişimini kapat
  -x           CWMP'yi aktif bırak
  -n           test çalıştırması
  -v           ayrıntılı çıktı
  -V           sürüm
```

## başlangıç

```sh
# windows (yönetici cmd)
tp-unlink.exe sifre31

# linux
sudo ./tp-unlink sifre31
```

başarılı olduktan sonra 192.168.1.1 adresine ssh/telnet ile bağlanabilirsiniz

## nasıl çalışır

1. 10.116.13.0/24 aralığından kendine ip atar
2. modemden gelen dhcp isteklerine sahte acs url içeren option 43 ile cevap verir
3. modem TR-069 için sahte acs'ye bağlanır
4. SetParameterValues ile root kullanıcıyı aktif eder
5. isp'nin ayarları geri almasını engellemek için cwmp'yi kapatır

değişiklik öncesi mevcut ayarlar `backup_YYYYMMDD_HHMMSS.xml` dosyasına yedeklenir

## return kodları

| kod | anlamı                 |
|-----|------------------------|
| 0   | başarılı               |
| 1   | hata                   |
| 2   | zaman aşımı (dhcp yok) |
| 3   | ağ hatası              |
| 4   | zaten etkin            |

## fabrika ayarlarına dönüş

```sh
tp-unlink -d
```

## notlar

- çalıştırmadan önce wan kablosunu çıkarın
- bazı modemlerde işlem sonrası yeniden başlatma gerekir
- vlan etiketli trafik algılanırsa işlem durur