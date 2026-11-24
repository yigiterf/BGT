# 🧩 Kavramlar Rehberi — Sıfırdan Firewall'a

Bu dosya, projede ve Chapter 10'da geçen **her terimi** en baştan, hiçbir ön bilgi varsaymadan anlatır. Amaç: bu rehberi okuduktan sonra projenin herhangi bir ekranına baktığında ("DENY", "implicit deny", "10.0.0.0/24", "SYN", "stateful") hiçbir kelimenin yabancı gelmemesi.

Sıradan oku — her bölüm bir öncekinin üzerine kuruluyor. Acelen yoksa önce bunu bitir, sonra [SUNUM_AKISI.md](SUNUM_AKISI.md)'ye geç.

---

## 1. En başa dönelim: iki bilgisayar nasıl konuşur?

İki bilgisayar internet üzerinden konuştuğunda, aralarında gidip gelen şey aslında küçük veri paketleri. Bunu posta sistemine benzetelim:

- Sen bir arkadaşına mektup gönderiyorsun.
- Mektubun üstünde **senin adresin** (gönderen) ve **arkadaşının adresi** (alıcı) yazıyor.
- Mektup, postane postane, yönlendirilerek hedefe ulaşıyor.

İnternette de aynı şey oluyor ama "adres" yerine **IP adresi** kullanılıyor.

---

## 2. IP adresi nedir?

**IP adresi**, internete bağlı her cihaza verilen, o cihazı tek başına tanımlayan bir numara. `10.0.0.10` gibi dört sayıdan oluşur (her biri 0-255 arası).

> **Analoji:** IP adresi, bir apartmanın **açık adresi**dir: "Atatürk Caddesi No:10". Postacı bu adrese bakarak hangi binaya gideceğini bilir.

Projede göreceğin bazı sabit IP'ler ve ne temsil ettikleri (bunlar proje boyunca hep aynı anlamda kullanılıyor):

| IP adresi | Projede temsil ettiği şey |
|---|---|
| `10.0.0.10` | **Web sunucusu** (şirketin internet sitesinin çalıştığı makine) |
| `10.0.0.53` | **DNS sunucusu** (alan adı çözümleme servisi) |
| `10.0.0.20` | **SSH sunucusu** (sistem yöneticisinin uzaktan bağlandığı makine) |
| `10.0.0.30` | **Veritabanı sunucusu** (müşteri/şirket verilerinin tutulduğu yer) |
| `198.51.100.66` | **Saldırgan** — dışarıdan, internetten gelen kötü niyetli biri |
| `203.0.113.0/24` | **Ofis ağı** — şirketin güvenilir, bilinen iç çalışan ağı |

Bu altı aktörü aklında tut; her senaryoda hep bunlar arasındaki ilişki değişiyor.

### CIDR nedir? (`10.0.0.0/24` gibi ifadeler)

Bazen tek bir IP değil, **bir aralık** belirtmek gerekir — "ofisteki bütün bilgisayarlar" gibi. Buna **CIDR notasyonu** denir: `203.0.113.0/24` demek, `203.0.113.0` ile `203.0.113.255` arasındaki **256 adresin tamamı** demektir.

> **Analoji:** Tek bir IP bir apartman dairesidir (`10.0.0.20`). CIDR ise bir **sokağın tamamı**dır (`10.0.0.0/24` = "bu sokaktaki tüm daireler"). `/24` sayısı sokağın ne kadar büyük olduğunu belirler — ne kadar düşükse (örn. `/8`) o kadar geniş bir bölge kapsar.

---

## 3. Port nedir?

Bir bilgisayarda aynı anda onlarca program internete açık olabilir: tarayıcı, mail programı, oyun sunucusu... Hepsi aynı IP adresini paylaşıyor. Peki gelen bir paket hangi programa ait olduğu nereden belli olacak? İşte bunun için **port** var.

> **Analoji:** IP adresi apartmanın adresiyse, **port apartmandaki daire numarasıdır**. Postacı binaya geldi (doğru IP), ama hangi daireye (hangi programa) teslim edeceğini **daire numarasından (port)** anlar.

Port, 0 ile 65535 arasında bir sayı. Bazı sayılar, dünya çapında belirli servisler için **standart olarak ayrılmış** ("well-known ports") — bu proje boyunca sürekli bunları göreceksin:

| Port | Hangi servis | Projede nerede geçiyor |
|---|---|---|
| `80` | HTTP (şifresiz web sitesi) | Web sunucusu kuralları |
| `443` | HTTPS (şifreli web sitesi) | Web sunucusu kuralları, stateful senaryo |
| `22` | SSH (sunucuya uzaktan komut satırından bağlanma) | SSH bastion senaryosu |
| `53` | DNS (alan adını IP'ye çeviren servis, örn. google.com → 142.x.x.x) | DNS kuralları, DNS tüneli saldırısı |
| `3306` | MySQL (bir veritabanı yazılımı) | DMZ senaryosu |

---

## 4. Protokol nedir? (TCP / UDP / ICMP)

Protokol, iki bilgisayarın **nasıl** konuşacağına dair kurallar bütünü. Projede üç tanesi geçiyor:

- **TCP** — "garanti teslimat" protokolü. Göndermeden önce bir **el sıkışma** yapılır (bkz. Bölüm 5), paketlerin sırayla ve eksiksiz ulaştığından emin olunur. Web siteleri, SSH, dosya indirme gibi "hiçbir şey kaybolmasın" gereken her yerde kullanılır.
  > **Analoji:** İadeli taahhütlü mektup — postacı imza alır, kaybolursa fark edilir.
- **UDP** — "hızlı ama garantisiz" protokol. El sıkışma yok, paket direkt gönderilir, karşı taraf aldı mı diye kontrol edilmez. DNS sorguları ve canlı yayın/oyun gibi "hız önemli, ufak kayıp önemli değil" durumlarda kullanılır.
  > **Analoji:** Kartpostal — postaya atarsın, ulaşıp ulaşmadığını bilmezsin ama hızlıdır.
- **ICMP** — veri taşımaz, **kontrol/durum mesajı** taşır. En bilinen örneği `ping` komutu: "Oradamısın?" diye sorar, "Evet buradayım" cevabı gelir. Projede "ping sweep" saldırısında kullanılıyor (ağdaki canlı makineleri keşfetmek için).

---

## 5. TCP bayrakları (flags) — SYN, ACK, PSH ne demek?

TCP bir bağlantı kurarken küçük bir "el sıkışma" yapar, buna **3-way handshake** denir:

```text
Bilgisayar A                      Bilgisayar B (sunucu)
     │  "Bağlanmak istiyorum" (SYN)     │
     │ ───────────────────────────────▶ │
     │  "Tamam, ben de hazırım" (SYN ACK)│
     │ ◀─────────────────────────────── │
     │  "Harika, başlıyoruz" (ACK)      │
     │ ───────────────────────────────▶ │
```

- **SYN** = "bağlantı başlatmak istiyorum" (ilk paket, her bağlantı bununla başlar)
- **ACK** = "önceki mesajı aldım, onaylıyorum"
- **SYN ACK** = "senin SYN'ini aldım, ben de bağlanmak istiyorum"
- **PSH ACK** = "burada gerçek veri var, hemen işle" (örneğin SSH brute-force saldırısında şifre denemeleri bu bayrakla gönderilir)

Projede saldırı senaryolarında bu bayrakları göreceksin — örneğin "SYN seli" saldırısı, sadece ilk el sıkışma paketini (SYN) gönderip cevabı hiç beklemeden yüzlercesini art arda yollar.

---

## 6. Paket nedir?

Yukarıdaki her şeyi bir araya koyarsak: bir **paket**, internette gidip gelen tek bir veri biriminin adı. Projede bir paket şu bilgileri taşıyan küçük bir not gibi düşünülüyor:

```text
Kimden:      198.51.100.66   (kaynak IP)
Kime:        10.0.0.20       (hedef IP)
Protokol:    tcp
Kimin portu: 51234            (kaynak port — genelde rastgele/önemsiz)
Hangi porta: 22                (hedef port — hangi servise gidiyor, ÖNEMLİ)
Bayrak:      SYN
```

Bu altı bilgiye birden **5-tuple** denir (kaynak IP, hedef IP, protokol, kaynak port, hedef port — 5 alan; bayrak TCP'ye özel bir ekstra). **Bir firewall'un gördüğü şey tam olarak budur — ne fazlası ne eksiği.** Paketin "içeriğini" (mesela bir web sayfasının gerçek yazısını, bir SSH şifresinin gerçek karakterlerini) normal bir firewall göremez — sadece bu zarftaki bilgiye bakar.

---

## 7. Firewall nedir?

Artık tüm parçalar elimizde — şimdi asıl soruya gelebiliriz.

**Firewall (güvenlik duvarı)**, bir ağa giren/çıkan her paketi inceleyip **"bu paket geçsin mi, engellensin mi?"** kararını veren bir sistem (donanım, yazılım ya da ikisinin karışımı olabilir).

> **Analoji:** Bir apartmanın girişindeki **güvenlik görevlisi**. Her gelen kişiye bakar: "Sen kimsin (hangi IP'den geliyorsun), hangi daireye gidiyorsun (hangi porta), ne iş için geldin (hangi protokol)?" Elindeki listeye (kurallara) bakar, listedeyse içeri alır, değilse kapıda durdurur.

Firewall, paketin **içeriğini okumaz** (mektubun içini açıp okumaz), sadece zarftaki bilgiye (5-tuple'a) bakar. Bu, projenin en çok vurguladığı sınırlardan biri — ileride "Sınırlamalar" bölümünde buna geri döneceğiz (DNS tüneli saldırısı tam olarak bu sınırı gösteriyor).

---

## 8. Paket filtreleme (packet filtering) nedir?

**Paket filtreleme**, firewall'un karar verme **yöntemi**. Her paketi, önceden yazılmış bir **kural listesine** (ACL) karşı tek tek kontrol eder — "bu paket şu kurala uyuyor mu?" diye sırayla sorar, uyan ilk kuralın dediğini yapar.

Önemli nokta: **temel paket filtreleme hafızasızdır** — her paketi, daha önce ne olduğunu hiç bilmeden, sıfırdan değerlendirir. (Bu sınırı aşan yönteme "stateful inspection" deniyor, Bölüm 11'de göreceğiz.)

---

## 9. ACL (Access Control List) — kural listesi nedir?

**ACL**, firewall'un elindeki kural listesinin adı — güvenlik görevlisinin elindeki "kimler girebilir" listesi. Projede her kural şöyle görünür:

```text
allow tcp any any 10.0.0.10 443   # HTTPS - herkese açık
```

Türkçesi: *"Protokolü TCP olan, kaynağı (gönderen) her yerden, hedefi 10.0.0.10 (web sunucumuz) ve hedef portu 443 (HTTPS) olan paketlere İZİN VER."*

Her kuralın 4 ana bileşeni var: **kaynak** (kim gönderiyor), **hedef** (nereye gidiyor), **protokol/port** (hangi servis), **eylem** (izin ver / engelle).

### Allow / Deny

- **Allow (izin ver)** — paket geçer, hedefe ulaşır.
- **Deny (engelle)** — paket orada durdurulur, hedefe hiç ulaşmaz.

### "İlk eşleşen kazanır" (first match wins)

Kurallar **sırayla** yukarıdan aşağı denenir. Bir paket birden fazla kurala uyabilir, ama firewall sadece **ilk uyan kuralın** dediğini yapar, gerisine bakmaz bile. Bu yüzden **kuralların sırası kuralların kendisi kadar önemlidir.** Projedeki "8 - Hatalı kural sırası" senaryosu tam olarak bunu gösteriyor: geniş bir izin kuralı en üstte olursa, altındaki yasak kuralı **asla çalışmaz** hale getirir.

### Varsayılan politika ve Implicit Deny (örtük/varsayılan red)

Peki bir paket **hiçbir kurala uymazsa** ne olur? İşte burada **varsayılan politika** devreye girer — listenin en sonunda, yazılı olmayan ama her zaman geçerli olan bir "son karar":

- Varsayılan politika **ALLOW** ise: hiçbir kurala uymayan paket bile geçer. Buna pratikte "açık firewall" denir — neredeyse hiçbir koruma sağlamaz.
- Varsayılan politika **DENY** ise: hiçbir kurala uymayan her paket otomatik olarak engellenir. Buna **implicit deny** (örtük/varsayılan red) denir — bilgi güvenliğinin altın kurallarından biri: **"açıkça izin vermediğin her şey yasaktır."**

> **Analoji:** Güvenlik görevlisinin elinde sadece "girebilir" listesi var, "giremez" listesi yok. Listede adı olmayan **herkes** otomatik olarak geri çevrilir — bu implicit deny'dir. Tam tersi: eğer görevliye "listede yazmayan herkesi içeri al" denirse, bu açık firewall'dur.

---

## 10. Stateful inspection nedir?

Bölüm 8'de "temel paket filtreleme hafızasızdır" dedik. Bunun yarattığı bir sorun var: Diyelim ki iç ağdaki bir bilgisayar, dışarıdaki bir web sitesine bağlandı (HTTPS isteği gönderdi, buna izin veren bir kural var). Web sitesi **cevap** gönderdiğinde, bu cevap paketi de firewall'dan geçmek zorunda. Ama kural listesinde "dışarıdan gelen cevaplara izin ver" diye bir kural yazmadıysak, bu **meşru cevap paketi bile engellenir!**

**Stateful inspection**, bu sorunu çözüyor: firewall, izin verdiği her bağlantıyı bir **"oturum tablosuna"** (hafızaya) yazıyor. Karşı taraftan gelen cevap paketlerini, kural listesine hiç bakmadan, "bu zaten bildiğim bir konuşmanın parçası" diyerek direkt geçiriyor.

> **Analoji:** Güvenlik görevlisi birini içeri aldı. O kişi dışarı çıkıp tekrar geldiğinde, görevli onu **tanıdığı için** tekrar listeye bakmadan içeri alır — "zaten seni biliyorum, az önce buradaydın."

---

## 11. Network separation / DMZ nedir?

Bir şirketin ağını tek bir büyük oda gibi düşünme — genelde **bölgelere ayrılır**:

- **Dış dünya (internet)** — herkesin erişebildiği, güvenilmeyen bölge.
- **DMZ (Demilitarized Zone — "silahsızlandırılmış bölge")** — dışarıya açık servislerin (web sitesi gibi) durduğu, ama hassas verilerin olmadığı **ara bölge**.
- **İç ağ** — veritabanı, çalışan bilgisayarları gibi hassas/kritik sistemlerin olduğu, dışarıdan **doğrudan erişilemeyen** bölge.

Mantık şu: web sunucusu internete açık olduğu için bir gün ele geçirilebilir (hacklenebilir). Eğer web sunucusu doğrudan veritabanına erişebiliyorsa, web sunucusunu ele geçiren saldırgan **veritabanına da** ulaşır. DMZ mimarisinde, web sunucusu ile veritabanı **arasına da bir firewall kuralı** konur: "DMZ'deki makineler veritabanına **doğrudan** bağlanamaz, sadece uygulama sunucusu bağlanabilir." Böylece web sunucusu ele geçirilse bile saldırgan bir adım daha atamaz.

> **Analoji:** Bir binanın girişindeki resepsiyon (DMZ) herkese açıktır. Ama resepsiyondan doğrudan **kasa dairesine (veritabanı)** geçiş yoktur — oraya sadece belirli, yetkili bir kapıdan (uygulama sunucusu) girilir.

---

## 12. Flood guard ve DDoS farkı nedir?

**Flood guard (taşkın koruması)**, bir kaynağın **çok kısa sürede çok fazla paket** göndermesini engelleyen bir mekanizma. Mantık: "normal bir kullanıcı saniyede 30'dan fazla istek göndermez, bu kadar hızlı istek gönderen biri muhtemelen saldırıyordur."

Ama burada kritik bir sınır var: Bu koruma **"kaynak IP başına"** çalışır. Yani:

- **Tek bir saldırgan** (`198.51.100.66`), saniyede 150 paket gönderirse → hızla limiti aşar, çoğu engellenir. Buna **DoS (Denial of Service — tek kaynaklı hizmet engelleme)** denir ve flood guard bunu durdurabilir.
- **Yüzlerce farklı, sahte IP'den** (bir "botnet" — ele geçirilmiş binlerce bilgisayardan oluşan ordu) gelen saldırıda, **her IP kendi başına** limitin çok altında kalır (örneğin her biri saniyede sadece 1 paket gönderiyor gibi görünür). Buna **DDoS (Distributed Denial of Service — dağıtık hizmet engelleme)** denir ve kaynak-bazlı flood guard **bunu durduramaz.**

> **Analoji:** Kapıda tek bir kişi sürekli girip çıkarak görevliyi yorsa, görevli onu fark edip durdurabilir (DoS). Ama aynı anda 500 farklı kişi birer kere gelirse, görevli her birini "normal bir ziyaretçi" sanır — oysa hepsi aynı kişi tarafından yönlendiriliyordur (DDoS).

---

## 13. Projedeki saldırı türleri ne anlama geliyor?

| Saldırı | Gerçek hayatta ne demek |
|---|---|
| **Port taraması (port scan)** | Saldırganın, hedef makinede **hangi portların açık** olduğunu anlamak için sırayla tüm portlara (1'den başlayarak + bilinen servis portlarına) birer paket göndermesi. "Hangi kapılar kilitli, hangileri açık?" diye kapı kapı denemek gibi. Genelde bir saldırının **ilk adımı**dır (keşif). |
| **SYN seli (SYN flood)** | Tek kaynaktan, art arda yüzlerce bağlantı başlatma isteği (SYN) gönderip cevap beklemeden devam etme. Amaç hedefi veya aradaki firewall'u **yormak**. |
| **DDoS (botnet)** | Aynı SYN seli, ama tek kaynaktan değil, **yüzlerce farklı (çoğunlukla sahte/ele geçirilmiş) IP'den** aynı anda. Bölüm 12'deki flood guard sınırını göstermek için var. |
| **SSH brute force** | Saldırganın, SSH servisine (port 22) art arda farklı şifre kombinasyonlarıyla giriş denemesi ("deneme1", "deneme2"...). Amaç şifre tahmin ederek içeri sızmak. |
| **DNS tüneli (DNS tunnel)** | Normalde DNS, sadece "bu alan adının IP'si nedir?" diye küçük sorgular yapar. Ama port 53 çoğu firewall'da **açık** olduğu için, saldırganlar bazen bu kanalı **gizlice veri sızdırmak** için kötüye kullanır — normal DNS sorgusu gibi görünen ama içinde büyük/anormal veri taşıyan paketler gönderirler. Bu saldırı projede **bilerek geçiyor** çünkü motor sadece port/protokole bakıyor, içeriği okumuyor — bu, "application layer" koruması olmadan DNS tünelinin neden yakalanamadığını gösteriyor. |
| **Ping sweep** | ICMP (ping) paketleriyle, bir ağdaki hangi IP'lerin **canlı/erişilebilir** olduğunu keşfetmeye çalışmak. Port taramasından önceki, daha da ilkel bir keşif adımı. |
| **DMZ → DB** | Web sunucusunun (DMZ'deki makine), kurallara göre erişemeyeceği veritabanına **doğrudan bağlanmaya çalışması** — DMZ ayrımının gerçekten işe yarayıp yaramadığını test eden tek paketlik bir deneme. |

---

## 14. Kural analizi (lint) ne demek?

Yazılımcıların kullandığı "lint" terimi, kodu **çalıştırmadan** hatalarını bulmaya çalışan statik analiz anlamına gelir. Projede bu, kural listesine uygulanıyor — kuralları **birbirleriyle karşılaştırıp** mantık hatalarını buluyor:

- **Gölgelenmiş (shadowed) kural** — bir kuralın üstünde, onu tamamen kapsayan başka bir kural var; bu yüzden alttaki kural **asla çalışmaz** (ilk eşleşen kazanır kuralı yüzünden). Eylemler (allow/deny) farklıysa bu gerçek bir güvenlik açığıdır.
- **Gereksiz (redundant) kural** — üstteki kural zaten aynı işi, aynı sonuçla yapıyor; bu kural fazlalık.
- **Çok geniş (broad) kural** — `any → any` gibi hemen hemen her şeye izin veren bir kural; "en az yetki" ilkesine aykırı.

---

## 15. iptables nedir?

**iptables**, Linux işletim sisteminin **gerçek, üretimde kullanılan** firewall aracının adı. Projedeki kural dili ("allow tcp any any 10.0.0.10 443") bir öğretim amaçlı basitleştirme; `export.py` bunu gerçek iptables komutuna çevirebiliyor:

```bash
iptables -A FORWARD -p tcp -d 10.0.0.10/32 --dport 443 -m comment --comment "HTTPS" -j ACCEPT
```

Bu, projenin "bu sadece oyuncak değil, gerçek dünyadaki karşılığı bu" bağını kurduğu yer.

---

## 16. Hepsini birleştirirsek — bir cümlede

Bir firewall, üzerinden geçen her paketin **kim gönderdi (IP), nereye gidiyor (IP), hangi servis için (port), hangi protokolle (TCP/UDP/ICMP)** olduğuna bakar; bunu önceden tanımlanmış bir **kural listesine (ACL)** sırayla karşılaştırır; **ilk uyan kuralın** izin/engel kararını uygular; hiçbir kural uymazsa **varsayılan politikaya** (genelde implicit deny) döner; ve isterse önceden izin verdiği bağlantıları **hafızasında tutarak (stateful)** onların cevaplarını otomatik geçirir. Bu proje, tam olarak bu cümleyi kodlar.

---

*Sırada: [SUNUM_AKISI.md](SUNUM_AKISI.md) — bu kavramların her birini canlı olarak hangi senaryoda, hangi butonla göstereceğin.*
